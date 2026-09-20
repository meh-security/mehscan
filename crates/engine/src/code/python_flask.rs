use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, ResourcePolicyContext,
    ResourcePolicyState,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan python-flask-project-context 1";
const HANDLER_RULE: &str = "python-flask-handler-entrypoint";
const PARAMETER_RULE: &str = "python-flask-route-parameter";
const OPENAPI_HANDLER_RULE: &str = "python-connexion-openapi-handler-entrypoint";
const OPENAPI_PARAMETER_RULE: &str = "python-openapi-operation-parameter";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OpenApiOperation {
    module: String,
    function: String,
    method: String,
    path: String,
    parameters: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PythonFlaskContext {
    blueprint_prefixes: BTreeMap<String, String>,
    sql_helpers: BTreeMap<String, BTreeMap<String, Vec<usize>>>,
    unique_python_modules: BTreeSet<String>,
    openapi_operations: BTreeMap<String, Vec<OpenApiOperation>>,
    is_flask_project: bool,
}

impl PythonFlaskContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut blueprint_prefixes = BTreeMap::new();
        let mut sql_helpers = BTreeMap::new();
        let mut module_counts = BTreeMap::<String, usize>::new();
        let mut is_flask_project = false;
        for (path, language, source) in sources {
            if language != Language::Python {
                continue;
            }
            is_flask_project |= source.contains("from flask import")
                || source.contains("import flask")
                || source.contains("Flask(")
                || source.contains("import connexion")
                || source.contains("from connexion import");
            if let Some(module) = python_module_stem(path) {
                *module_counts.entry(module.clone()).or_default() += 1;
                sql_helpers
                    .entry(module)
                    .or_insert_with(BTreeMap::new)
                    .extend(unsafe_sql_helpers(source));
            }
            for call in named_calls(source, "register_blueprint") {
                let arguments = split_arguments(call);
                let Some(blueprint) = arguments.first().map(|value| value.trim()) else {
                    continue;
                };
                let Some(prefix) = arguments.iter().find_map(|argument| {
                    argument
                        .trim()
                        .strip_prefix("url_prefix=")
                        .and_then(string_literal)
                }) else {
                    continue;
                };
                blueprint_prefixes.insert(blueprint.to_string(), prefix);
            }
        }
        sql_helpers.retain(|module, _| module_counts.get(module) == Some(&1));
        let unique_python_modules = module_counts
            .into_iter()
            .filter_map(|(module, count)| (count == 1).then_some(module))
            .collect();
        Self {
            blueprint_prefixes,
            sql_helpers,
            unique_python_modules,
            openapi_operations: BTreeMap::new(),
            is_flask_project,
        }
    }

    pub(crate) fn with_openapi<'a>(
        mut self,
        documents: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        for (_, source) in documents {
            for operation in parse_openapi_operations(source) {
                if !self.unique_python_modules.contains(&operation.module) {
                    continue;
                }
                self.openapi_operations
                    .entry(format!("{}.{}", operation.module, operation.function))
                    .or_default()
                    .push(operation);
            }
        }
        for operations in self.openapi_operations.values_mut() {
            operations.sort();
            operations.dedup();
        }
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if language != Language::Python {
            return;
        }
        if !self.is_flask_project {
            return;
        }
        add_session_and_cookie_policy(path, root, comments, conditional, literals, evidence);
        add_flask_runtime_policy(path, root, comments, conditional, literals, evidence);
        add_sqlalchemy_access(path, root, comments, conditional, literals, evidence);
        add_dbapi_cursor_queries(path, root, comments, conditional, literals, evidence);
        add_jinja_template_evaluations(path, root, comments, conditional, literals, evidence);
        self.add_module_sql_summaries(path, root, comments, conditional, literals, evidence);

        for function in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "function_definition")
        {
            let decorated_routes = self.decorated_routes_for(&function);
            let openapi_operations = self.openapi_for(path, &function);
            let mut routes = decorated_routes.clone();
            routes.extend(openapi_operations.iter().map(|operation| HttpRouteContext {
                method: operation.method.clone(),
                path: operation.path.clone(),
                access: HttpRouteAccess::Unknown,
                guards: Vec::new(),
            }));
            routes.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then(left.method.cmp(&right.method))
            });
            routes.dedup();
            if routes.is_empty() {
                continue;
            }
            let Some(name) = function.field("name") else {
                continue;
            };
            let range = function.range();
            push_handler(
                path,
                &name,
                routes.clone(),
                if decorated_routes.is_empty() {
                    OPENAPI_HANDLER_RULE
                } else {
                    HANDLER_RULE
                },
                if decorated_routes.is_empty() {
                    "connexion-openapi"
                } else {
                    "flask"
                },
                comments,
                conditional,
                literals,
                evidence,
            );
            push_route_parameters(
                path,
                &function,
                &routes,
                comments,
                conditional,
                literals,
                evidence,
            );
            push_openapi_parameters(
                path,
                &function,
                &openapi_operations,
                comments,
                conditional,
                literals,
                evidence,
            );
            add_raw_flask_responses(path, &function, comments, conditional, literals, evidence);
            for item in evidence.iter_mut().filter(|item| {
                item.location.path == path
                    && item.rule_id != PARAMETER_RULE
                    && item.location.start.byte_offset >= range.start
                    && item.location.end.byte_offset <= range.end
            }) {
                for route in &routes {
                    if !item.context.http_routes.contains(route) {
                        item.context.http_routes.push(route.clone());
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_module_sql_summaries<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
            let Some(function) = call.field("function") else {
                continue;
            };
            let function_text = function.text();
            let Some((module, helper)) = function_text.trim().split_once('.') else {
                continue;
            };
            if helper.contains('.') {
                continue;
            }
            let Some(indices) = self
                .sql_helpers
                .get(module)
                .and_then(|helpers| helpers.get(helper))
            else {
                continue;
            };
            let arguments = call_arguments(&call);
            for index in indices {
                let Some(argument) = arguments.get(*index) else {
                    continue;
                };
                push(
                    path,
                    argument,
                    EvidenceKind::Sink,
                    Capability::DatabaseQuery,
                    "python-module-qualified-sql-helper-summary",
                    &["CWE-89"],
                    vec![
                        "python",
                        "database",
                        "module-qualified-helper",
                        "formatted-sql-parameter",
                        "bounded-one-hop-summary",
                    ],
                    "query",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    fn decorated_routes_for(
        &self,
        function: &Node<'_, StrDoc<SupportLang>>,
    ) -> Vec<HttpRouteContext> {
        let Some(decorated) = function
            .parent()
            .filter(|node| node.kind().as_ref() == "decorated_definition")
        else {
            return Vec::new();
        };
        let access = flask_access(function, &decorated);
        let mut routes = Vec::new();
        for decorator in decorated
            .children()
            .filter(|node| node.kind().as_ref() == "decorator")
        {
            let compact = compact(decorator.text().as_ref());
            let decorator_call = compact.trim_start_matches('@');
            let Some(route_at) = decorator_call.find(".route(") else {
                continue;
            };
            let receiver = decorator_call.get(..route_at).unwrap_or_default();
            let arguments =
                &decorator_call[route_at + ".route(".len()..decorator_call.len().saturating_sub(1)];
            let arguments = split_arguments(arguments);
            let Some(path) = arguments.first().and_then(|value| string_literal(value)) else {
                continue;
            };
            let prefix = self
                .blueprint_prefixes
                .get(receiver)
                .map(String::as_str)
                .unwrap_or_default();
            let joined = join_route(prefix, &path);
            let methods = arguments
                .iter()
                .find_map(|argument| argument.strip_prefix("methods="))
                .map(string_literals)
                .filter(|methods| !methods.is_empty())
                .unwrap_or_else(|| vec!["GET".to_string()]);
            for method in methods {
                routes.push(HttpRouteContext {
                    method: method.to_ascii_uppercase(),
                    path: joined.clone(),
                    access,
                    guards: flask_guards(function, &decorated),
                });
            }
        }
        routes.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.method.cmp(&right.method))
        });
        routes.dedup();
        routes
    }

    fn openapi_for(
        &self,
        path: &str,
        function: &Node<'_, StrDoc<SupportLang>>,
    ) -> Vec<OpenApiOperation> {
        let Some(module) = python_module_stem(path) else {
            return Vec::new();
        };
        let Some(name) = function.field("name") else {
            return Vec::new();
        };
        self.openapi_operations
            .get(&format!("{module}.{}", name.text().trim()))
            .cloned()
            .unwrap_or_default()
    }
}

#[allow(clippy::too_many_arguments)]
fn add_dbapi_cursor_queries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for function in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
    {
        let scope = function.range();
        let receivers = function
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment")
            .filter(|node| directly_in_function(node, &scope))
            .filter_map(|assignment| {
                let left = assignment.field("left")?;
                let right = assignment.field("right")?;
                let name = left.text();
                (left.kind().as_ref() == "identifier"
                    && compact(right.text().as_ref()).ends_with(".cursor()"))
                .then(|| name.trim().to_string())
            })
            .collect::<BTreeSet<_>>();
        if receivers.is_empty() {
            continue;
        }
        for call in function
            .dfs()
            .filter(|node| node.kind().as_ref() == "call")
            .filter(|node| directly_in_function(node, &scope))
        {
            let Some(callee) = call.field("function") else {
                continue;
            };
            let callee = callee.text();
            let Some((receiver, method)) = callee.trim().rsplit_once('.') else {
                continue;
            };
            if !receivers.contains(receiver)
                || !matches!(method, "execute" | "executemany" | "executescript")
            {
                continue;
            }
            let arguments = call_arguments(&call);
            let Some(query) = arguments.first() else {
                continue;
            };
            let query_value = resolve_local_value(&function, &scope, query, call.range().start)
                .unwrap_or_else(|| query.clone());
            push(
                path,
                &query_value,
                EvidenceKind::Sink,
                Capability::DatabaseQuery,
                "python-proved-dbapi-cursor-query",
                &["CWE-89"],
                vec!["python", "database", "db-api", "proved-cursor-receiver"],
                "query",
                comments,
                conditional,
                literals,
                evidence,
            );
            if let Some(parameters) = arguments.get(1) {
                push(
                    path,
                    parameters,
                    EvidenceKind::Sanitizer,
                    Capability::SqlParameterization,
                    "python-proved-dbapi-parameterization",
                    &["CWE-89"],
                    vec!["python", "database", "db-api", "bound-parameters"],
                    "parameters",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_raw_flask_responses<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let scope = function.range();
    for returned in function
        .dfs()
        .filter(|node| node.kind().as_ref() == "return_statement")
        .filter(|node| directly_in_function(node, &scope))
    {
        let Some(value) = returned
            .children()
            .find(|child| !matches!(child.kind().as_ref(), "return" | "," | "(" | ")"))
        else {
            continue;
        };
        let value_text = compact(value.text().as_ref());
        if value_text.is_empty()
            || value_text.starts_with('{')
            || value_text.starts_with("redirect(")
            || value_text.starts_with("flask.redirect(")
            || value_text.starts_with("render_template(")
            || value_text.starts_with("jsonify(")
            || matches!(value.kind().as_ref(), "dictionary" | "list")
        {
            continue;
        }
        let dynamic = value.dfs().any(|node| {
            matches!(
                node.kind().as_ref(),
                "interpolation" | "concatenated_string" | "binary_operator"
            )
        });
        if dynamic {
            push(
                path,
                &value,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                "python-flask-raw-dynamic-response",
                &["CWE-79"],
                vec!["python", "flask", "raw-response", "dynamic-html"],
                "content",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_jinja_template_evaluations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut constructors = jinja_template_constructors(root);
    constructors.retain(|constructor| {
        let binding = constructor.split('.').next().unwrap_or(constructor);
        !root.dfs().any(|node| {
            (node.kind().as_ref() == "assignment"
                && node
                    .field("left")
                    .is_some_and(|left| left.text().trim() == binding))
                || (node.kind().as_ref() == "parameters"
                    && node.children().any(|parameter| {
                        parameter.kind().as_ref() == "identifier"
                            && parameter.text().trim() == binding
                    }))
        })
    });
    if constructors.is_empty() {
        return;
    }
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let Some(callee) = call.field("function") else {
            continue;
        };
        if !constructors.contains(callee.text().trim()) || !jinja_template_is_rendered(&call) {
            continue;
        }
        let Some(template) = call_arguments(&call).into_iter().next() else {
            continue;
        };
        push(
            path,
            &template,
            EvidenceKind::Sink,
            Capability::TemplateEvaluation,
            "python-jinja-dynamic-template-evaluation",
            &["CWE-1336"],
            vec![
                "python",
                "jinja2",
                "server-side-template-injection",
                "dynamic-template-source",
            ],
            "template",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn jinja_template_constructors(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut constructors = BTreeSet::new();
    for import in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        )
    }) {
        let text = import.text();
        let trimmed = text.trim();
        if let Some(items) = trimmed.strip_prefix("from jinja2 import ") {
            for item in items.split(',') {
                let item = item.trim();
                let (name, alias) = item
                    .split_once(" as ")
                    .map_or((item, item), |(name, alias)| (name.trim(), alias.trim()));
                if name == "Template" {
                    constructors.insert(alias.to_string());
                }
            }
        } else if let Some(items) = trimmed.strip_prefix("import ") {
            for item in items.split(',') {
                let item = item.trim();
                let (name, alias) = item
                    .split_once(" as ")
                    .map_or((item, item), |(name, alias)| (name.trim(), alias.trim()));
                if name == "jinja2" {
                    constructors.insert(format!("{alias}.Template"));
                }
            }
        }
    }
    constructors
}

fn jinja_template_is_rendered(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if call.ancestors().take(4).any(|ancestor| {
        ancestor.kind().as_ref() == "call"
            && ancestor.field("function").is_some_and(|function| {
                function.text().trim().ends_with(".render")
                    && function.range().start <= call.range().start
                    && function.range().end >= call.range().end
            })
    }) {
        return true;
    }
    let Some(assignment) = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "assignment")
    else {
        return false;
    };
    let Some(target) = assignment
        .field("left")
        .filter(|left| left.kind().as_ref() == "identifier")
    else {
        return false;
    };
    let Some(function) = assignment
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
    else {
        return false;
    };
    let scope = function.range();
    let rendered = format!("{}.render", target.text().trim());
    function.dfs().any(|node| {
        node.kind().as_ref() == "call"
            && node.range().start > assignment.range().end
            && directly_in_function(&node, &scope)
            && node
                .field("function")
                .is_some_and(|callee| callee.text().trim() == rendered)
    })
}

fn resolve_local_value<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    scope: &std::ops::Range<usize>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    before: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if value.kind().as_ref() != "identifier" {
        return None;
    }
    let name = value.text();
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment")
        .filter(|node| directly_in_function(node, scope) && node.range().end < before)
        .filter_map(|assignment| {
            let left = assignment.field("left")?;
            (left.kind().as_ref() == "identifier" && left.text().trim() == name.trim())
                .then(|| assignment.field("right"))
                .flatten()
        })
        .last()
}

fn directly_in_function(
    node: &Node<'_, StrDoc<SupportLang>>,
    function_range: &std::ops::Range<usize>,
) -> bool {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        .is_some_and(|ancestor| ancestor.range() == *function_range)
}

fn flask_access(
    function: &Node<'_, StrDoc<SupportLang>>,
    decorated: &Node<'_, StrDoc<SupportLang>>,
) -> HttpRouteAccess {
    let text = decorated.text().into_owned();
    if text.contains("@login_required") && imports_flask_login_required(decorated) {
        return HttpRouteAccess::Authenticated;
    }
    let body = function.text().into_owned();
    let session_deny = (body.contains("not in g.session") || body.contains("not in session"))
        && (body.contains("redirect(") || body.contains("401"));
    if session_deny {
        HttpRouteAccess::Authenticated
    } else {
        HttpRouteAccess::Unknown
    }
}

fn imports_flask_login_required(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .last()
        .map(|root| root.text().into_owned())
        .is_some_and(|source| {
            source.lines().any(|line| {
                let line = line.trim();
                line.starts_with("from flask_login import ")
                    && line["from flask_login import ".len()..]
                        .split(',')
                        .map(str::trim)
                        .any(|name| name == "login_required")
            })
        })
}

fn flask_guards(
    function: &Node<'_, StrDoc<SupportLang>>,
    decorated: &Node<'_, StrDoc<SupportLang>>,
) -> Vec<String> {
    let mut guards = Vec::new();
    let decorated_text = decorated.text();
    if decorated_text.contains("@login_required") {
        guards.push("login_required".to_string());
    }
    if decorated_text.contains("@auth_required") {
        guards.push("auth_required".to_string());
    }
    let body = function.text();
    if (body.contains("not in g.session") || body.contains("not in session"))
        && (body.contains("redirect(") || body.contains("401"))
    {
        guards.push("local-session-deny-guard".to_string());
    }
    if body.contains("authenticate(request)") && (body.contains("if not ") || body.contains("401"))
    {
        guards.push("local-api-authentication-deny-guard".to_string());
    }
    guards
}

#[allow(clippy::too_many_arguments)]
fn add_session_and_cookie_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let root_text = root.text().into_owned();
    let mut unsigned_session_emitted = false;
    let mut authenticated_session_emitted = false;
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let callee = call
            .field("function")
            .map(|node| node.text().into_owned())
            .unwrap_or_default();
        if !unsigned_session_emitted
            && callee.ends_with("base64.b64decode")
            && root_text.contains("request.cookies")
            && root_text.contains("json.loads")
            && !root_text.contains("hmac.compare_digest")
            && !root_text.contains("Fernet(")
        {
            push(
                path,
                &call,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                "python-flask-unsigned-client-session",
                &["CWE-345", "CWE-565"],
                vec![
                    "flask",
                    "session",
                    "client-controlled-identity",
                    "encoding-without-authentication",
                    "recommendation:fix-application",
                ],
                "session",
                comments,
                conditional,
                literals,
                evidence,
            );
            unsigned_session_emitted = true;
        } else if !authenticated_session_emitted
            && callee.ends_with("decrypt")
            && root_text.contains("Fernet(")
            && root_text.contains("request.cookies")
        {
            push(
                path,
                &call,
                EvidenceKind::Validation,
                Capability::Authentication,
                "python-flask-authenticated-session-control",
                &[],
                vec![
                    "flask",
                    "session",
                    "authenticated-encryption",
                    if call.text().contains("ttl=") {
                        "expiry-enforced"
                    } else {
                        "expiry-not-observed"
                    },
                ],
                "session",
                comments,
                conditional,
                literals,
                evidence,
            );
            authenticated_session_emitted = true;
        }
        if callee.ends_with("set_cookie") {
            let compact_call = compact(call.text().as_ref()).to_ascii_lowercase();
            if !compact_call.contains("session") && !compact_call.contains("auth") {
                continue;
            }
            if compact_call.contains("expires=0") || compact_call.contains("max_age=0") {
                continue;
            }
            let secure = compact_call.contains("secure=true");
            let http_only = compact_call.contains("httponly=true");
            let same_site = compact_call.contains("samesite=");
            let controlled = secure && http_only && same_site;
            push(
                path,
                &call,
                if controlled {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SecurityConfiguration
                },
                Capability::CookieConfiguration,
                if controlled {
                    "python-flask-session-cookie-control"
                } else {
                    "python-flask-session-cookie-flags-review"
                },
                if controlled {
                    &[]
                } else {
                    &["CWE-614", "CWE-1004", "CWE-1275"]
                },
                vec![
                    "flask",
                    "session-cookie",
                    if secure {
                        "secure"
                    } else {
                        "secure-not-observed"
                    },
                    if http_only {
                        "httponly"
                    } else {
                        "httponly-not-observed"
                    },
                    if same_site {
                        "samesite"
                    } else {
                        "samesite-not-observed"
                    },
                    if controlled {
                        "control"
                    } else {
                        "recommendation:fix-cookie-policy"
                    },
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_flask_runtime_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| {
        node.kind().as_ref() == "call"
            && node
                .field("function")
                .is_some_and(|function| function.text().ends_with(".run"))
            && compact(node.text().as_ref()).contains("debug=True")
    }) {
        let exposed = compact(call.text().as_ref()).contains("host=\"0.0.0.0\"")
            || compact(call.text().as_ref()).contains("host='0.0.0.0'");
        push(
            path,
            &call,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            "python-flask-debug-server-review",
            &["CWE-489"],
            vec![
                "flask",
                "development-server",
                "debug-enabled",
                if exposed {
                    "externally-bound"
                } else {
                    "loopback-bound-or-unknown"
                },
                if exposed {
                    "recommendation:fix-application"
                } else {
                    "recommendation:review-runtime-entrypoint"
                },
            ],
            "policy",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_sqlalchemy_access<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let Some(function) = call.field("function") else {
            continue;
        };
        let callee = function.text().into_owned();
        if !(callee.contains(".query.get")
            || callee.contains(".query.filter_by")
            || callee.ends_with("session.get")
            || callee.ends_with("db.session.get"))
        {
            continue;
        }
        let arguments = call_arguments(&call);
        let Some(filter) = arguments.last() else {
            continue;
        };
        let call_text = call.text().into_owned();
        let owner_scoped = (call_text.contains("owner=") || call_text.contains("user="))
            && (call_text.contains("current_user") || call_text.contains("g.user"));
        let rule = if owner_scoped {
            "python-sqlalchemy-owner-scoped-control"
        } else {
            "python-sqlalchemy-resource-access"
        };
        let location = location(path, filter);
        evidence.push(Evidence {
            id: format!(
                "{path}:{}:{}:{rule}",
                filter.range().start,
                filter.range().end
            ),
            kind: if owner_scoped {
                EvidenceKind::Validation
            } else {
                EvidenceKind::Sink
            },
            capability: Capability::ResourceAccess,
            location: location.clone(),
            enclosing_symbol: enclosing_symbol(&call),
            captures: BTreeMap::from([(
                "filter".to_string(),
                Capture {
                    text: filter.text().into_owned(),
                    location,
                },
            )]),
            cwe_candidates: vec!["CWE-639".to_string()],
            tags: vec![
                "python".to_string(),
                "sqlalchemy".to_string(),
                if owner_scoped {
                    "owner-scoped-control"
                } else {
                    "verify-owner-or-tenant-policy"
                }
                .to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(filter.range()),
                reachability: Some(reachability::classify(filter, literals)),
                availability: Some(conditional.availability_for(filter.range())),
                resource_policy: Some(ResourcePolicyContext {
                    state: if owner_scoped {
                        ResourcePolicyState::OwnerScoped
                    } else {
                        ResourcePolicyState::Unknown
                    },
                    basis: if owner_scoped {
                        "SQLAlchemy predicate uses authenticated current-user identity"
                    } else {
                        "lookup key lacks a proved owner or tenant predicate"
                    }
                    .to_string(),
                }),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push_handler<'tree>(
    path: &str,
    name: &Node<'tree, StrDoc<SupportLang>>,
    routes: Vec<HttpRouteContext>,
    rule: &str,
    framework: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let location = location(path, name);
    evidence.push(Evidence {
        id: format!("{path}:{}:{}:{rule}", name.range().start, name.range().end),
        kind: EvidenceKind::Entrypoint,
        capability: Capability::HttpRequestHandling,
        location: location.clone(),
        enclosing_symbol: Some(name.text().into_owned()),
        captures: BTreeMap::from([(
            "handler".to_string(),
            Capture {
                text: name.text().into_owned(),
                location,
            },
        )]),
        cwe_candidates: vec!["CWE-306".to_string(), "CWE-862".to_string()],
        tags: vec![
            "http".to_string(),
            framework.to_string(),
            "route".to_string(),
        ],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(name.range()),
            reachability: Some(reachability::classify(name, literals)),
            availability: Some(conditional.availability_for(name.range())),
            http_routes: routes,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule.to_string(),
        related_evidence: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_route_parameters<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    routes: &[HttpRouteContext],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = function.field("parameters") else {
        return;
    };
    for parameter in parameters
        .children()
        .filter(|node| node.kind().as_ref() == "identifier")
    {
        let name = parameter.text().into_owned();
        if !routes
            .iter()
            .any(|route| route_parameter_names(&route.path).any(|item| item == name))
        {
            continue;
        }
        let source = function
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "identifier"
                    && node.range().start > parameters.range().end
                    && node.text().trim() == name
            })
            .min_by_key(|node| node.range().start)
            .unwrap_or_else(|| parameter.clone());
        let location = location(path, &source);
        evidence.push(Evidence {
            id: format!(
                "{path}:{}:{}:{PARAMETER_RULE}",
                parameter.range().start,
                parameter.range().end
            ),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location.clone(),
            enclosing_symbol: enclosing_symbol(function),
            captures: BTreeMap::from([(
                "name".to_string(),
                Capture {
                    text: name,
                    location,
                },
            )]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "flask".to_string(),
                "route-parameter".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(source.range()),
                reachability: Some(reachability::classify(&source, literals)),
                availability: Some(conditional.availability_for(source.range())),
                http_routes: routes.to_vec(),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: PARAMETER_RULE.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push_openapi_parameters<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    operations: &[OpenApiOperation],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = function.field("parameters") else {
        return;
    };
    for parameter in parameters
        .children()
        .filter(|node| node.kind().as_ref() == "identifier")
    {
        let name = parameter.text().trim().to_string();
        let routes = operations
            .iter()
            .filter(|operation| operation.parameters.contains(&name))
            .map(|operation| HttpRouteContext {
                method: operation.method.clone(),
                path: operation.path.clone(),
                access: HttpRouteAccess::Unknown,
                guards: Vec::new(),
            })
            .collect::<Vec<_>>();
        if routes.is_empty() {
            continue;
        }
        let source = function
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "identifier"
                    && node.range().start > parameters.range().end
                    && node.text().trim() == name
            })
            .min_by_key(|node| node.range().start)
            .unwrap_or_else(|| parameter.clone());
        let location = location(path, &source);
        evidence.push(Evidence {
            id: format!(
                "{path}:{}:{}:{OPENAPI_PARAMETER_RULE}",
                parameter.range().start,
                parameter.range().end
            ),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location.clone(),
            enclosing_symbol: enclosing_symbol(function),
            captures: BTreeMap::from([(
                "name".to_string(),
                Capture {
                    text: name,
                    location,
                },
            )]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "connexion".to_string(),
                "openapi-operation-parameter".to_string(),
                "configuration-backed".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::External,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(source.range()),
                reachability: Some(reachability::classify(&source, literals)),
                availability: Some(conditional.availability_for(source.range())),
                http_routes: routes,
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: OPENAPI_PARAMETER_RULE.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule: &str,
    cwes: &[&str],
    tags: Vec<&str>,
    capture: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let location = location(path, node);
    evidence.push(Evidence {
        id: format!("{path}:{}:{}:{rule}", node.range().start, node.range().end),
        kind,
        capability,
        location: location.clone(),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            capture.to_string(),
            Capture {
                text: node.text().into_owned(),
                location,
            },
        )]),
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule.to_string(),
        related_evidence: Vec::new(),
    });
}

fn named_calls<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(&format!(".{name}(")) {
        let open = offset + relative + name.len() + 2;
        let mut depth = 1usize;
        let mut end = open;
        for (index, character) in source[open..].char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + index;
                        break;
                    }
                }
                _ => {}
            }
        }
        result.push(&source[open..end]);
        offset = end.saturating_add(1);
    }
    result
}

fn parse_openapi_operations(source: &str) -> Vec<OpenApiOperation> {
    let base_path = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("- url:").and_then(yaml_scalar))
        .unwrap_or_default();
    let mut operations = Vec::new();
    let mut in_paths = false;
    let mut current_path = None::<String>;
    let mut method = None::<String>;
    let mut operation_id = None::<String>;
    let mut parameters = Vec::<String>::new();
    let mut parameters_indent = None::<usize>;

    let flush = |operations: &mut Vec<OpenApiOperation>,
                 current_path: &Option<String>,
                 method: &mut Option<String>,
                 operation_id: &mut Option<String>,
                 parameters: &mut Vec<String>| {
        let (Some(path), Some(method), Some(operation_id)) =
            (current_path.as_ref(), method.take(), operation_id.take())
        else {
            parameters.clear();
            return;
        };
        let Some((module, function)) = operation_id.rsplit_once('.') else {
            parameters.clear();
            return;
        };
        if module.is_empty()
            || module.contains('.')
            || function.is_empty()
            || !module
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
            || !function
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            parameters.clear();
            return;
        }
        parameters.sort();
        parameters.dedup();
        operations.push(OpenApiOperation {
            module: module.to_string(),
            function: function.to_string(),
            method: method.to_ascii_uppercase(),
            path: join_route(&base_path, path),
            parameters: std::mem::take(parameters),
        });
    };

    for line in source.lines() {
        let indent = line.len().saturating_sub(line.trim_start().len());
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !in_paths {
            if trimmed == "paths:" {
                in_paths = true;
            }
            continue;
        }
        if indent == 0 {
            flush(
                &mut operations,
                &current_path,
                &mut method,
                &mut operation_id,
                &mut parameters,
            );
            break;
        }
        if indent == 2 && trimmed.starts_with('/') && trimmed.ends_with(':') {
            flush(
                &mut operations,
                &current_path,
                &mut method,
                &mut operation_id,
                &mut parameters,
            );
            current_path = Some(trimmed.trim_end_matches(':').to_string());
            parameters_indent = None;
            continue;
        }
        if indent == 4 && trimmed.ends_with(':') {
            let candidate = trimmed.trim_end_matches(':').to_ascii_lowercase();
            if matches!(
                candidate.as_str(),
                "get" | "post" | "put" | "patch" | "delete" | "options" | "head" | "trace"
            ) {
                flush(
                    &mut operations,
                    &current_path,
                    &mut method,
                    &mut operation_id,
                    &mut parameters,
                );
                method = Some(candidate);
                parameters_indent = None;
                continue;
            }
        }
        if method.is_none() {
            continue;
        }
        if trimmed == "parameters:" {
            parameters_indent = Some(indent);
            continue;
        }
        if parameters_indent.is_some_and(|start| indent <= start) {
            parameters_indent = None;
        }
        if let Some(value) = trimmed.strip_prefix("operationId:").and_then(yaml_scalar) {
            operation_id = Some(value);
        } else if let Some(value) = trimmed.strip_prefix("x-body-name:").and_then(yaml_scalar) {
            parameters.push(value);
        } else if parameters_indent.is_some()
            && let Some(value) = trimmed
                .strip_prefix("- name:")
                .or_else(|| trimmed.strip_prefix("name:"))
                .and_then(yaml_scalar)
        {
            parameters.push(value);
        }
    }
    if in_paths {
        flush(
            &mut operations,
            &current_path,
            &mut method,
            &mut operation_id,
            &mut parameters,
        );
    }
    operations
}

fn yaml_scalar(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || matches!(value, "|" | ">") {
        return None;
    }
    let unquoted = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
        .trim();
    (!unquoted.is_empty() && !unquoted.contains(['{', '}', '$'])).then(|| unquoted.to_string())
}

fn python_module_stem(path: &str) -> Option<String> {
    path.replace('\\', "/")
        .rsplit('/')
        .next()?
        .strip_suffix(".py")
        .map(str::to_string)
}

fn unsafe_sql_helpers(source: &str) -> BTreeMap<String, Vec<usize>> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut helpers = BTreeMap::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        let Some(signature) = line.strip_prefix("def ") else {
            index += 1;
            continue;
        };
        let Some((name, rest)) = signature.split_once('(') else {
            index += 1;
            continue;
        };
        let Some((parameters, _)) = rest.split_once(')') else {
            index += 1;
            continue;
        };
        let parameters = split_arguments(parameters)
            .into_iter()
            .map(|parameter| parameter.split('=').next().unwrap_or(parameter).trim())
            .filter(|parameter| !parameter.is_empty())
            .collect::<Vec<_>>();
        let start = index;
        index += 1;
        while index < lines.len() && !lines[index].starts_with("def ") {
            index += 1;
        }
        let body = lines[start..index].join("\n");
        let unsafe_query = body.contains(".execute(")
            && (body.contains(".format(")
                || body
                    .lines()
                    .any(|line| line.contains(".execute(") && line.contains('%'))
                || body
                    .lines()
                    .any(|line| line.contains(".execute(f\"") || line.contains(".execute(f'")));
        if !unsafe_query {
            continue;
        }
        let indices = parameters
            .iter()
            .enumerate()
            .filter_map(|(index, parameter)| body.contains(parameter).then_some(index))
            .collect::<Vec<_>>();
        if !indices.is_empty() {
            helpers.insert(name.trim().to_string(), indices);
        }
    }
    helpers
}

fn split_arguments(arguments: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    for (index, character) in arguments.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(arguments[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < arguments.len() {
        result.push(arguments[start..].trim());
    }
    result
}

fn string_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let quote = trimmed.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    Some(
        trimmed
            .strip_prefix(quote)?
            .strip_suffix(quote)?
            .to_string(),
    )
}
fn string_literals(text: &str) -> Vec<String> {
    split_arguments(text.trim().trim_start_matches('[').trim_end_matches(']'))
        .into_iter()
        .filter_map(string_literal)
        .collect()
}
fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
fn join_route(prefix: &str, path: &str) -> String {
    let left = prefix.trim_matches('/');
    let right = path.trim_matches('/');
    match (left.is_empty(), right.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{right}"),
        (false, true) => format!("/{left}"),
        (false, false) => format!("/{left}/{right}"),
    }
}
fn route_parameter_names(route: &str) -> impl Iterator<Item = &str> {
    route
        .split('<')
        .skip(1)
        .filter_map(|part| part.split('>').next())
        .map(|parameter| parameter.rsplit(':').next().unwrap_or(parameter))
}
fn call_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.children()
        .find(|node| node.kind().as_ref() == "argument_list")
        .map(|args| {
            args.children()
                .filter(|node| !matches!(node.kind().as_ref(), "(" | ")" | ","))
                .collect()
        })
        .unwrap_or_default()
}
fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}
