use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan go-project-context 1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct GoRoute {
    target_hint: String,
    method: String,
    path: String,
    access: HttpRouteAccess,
    guards: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MongoParameterRole {
    Filter,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MongoParameterSummary {
    index: usize,
    role: MongoParameterRole,
    dynamic_object: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqlParameterRole {
    UnsafeQuery,
    Parameterized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SqlParameterSummary {
    indices: Vec<usize>,
    role: SqlParameterRole,
    resource_filter_indices: Vec<usize>,
    mutates_resource: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LdapParameterSummary {
    filter_index: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GoProjectContext {
    routes_by_handler: BTreeMap<String, Vec<GoRoute>>,
    mongo_parameter_summaries: BTreeMap<String, Vec<MongoParameterSummary>>,
    sql_parameter_summaries: BTreeMap<String, SqlParameterSummary>,
    ldap_parameter_summaries: BTreeMap<String, LdapParameterSummary>,
    cookie_return_helpers: BTreeSet<String>,
    session_value_helpers: BTreeSet<String>,
    uses_cookie_session_auth: bool,
    has_csrf_control: bool,
}

impl GoProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| *language == Language::Go)
            .collect::<Vec<_>>();
        let function_names = sources
            .iter()
            .flat_map(|(_, _, source)| go_function_names(source))
            .collect::<BTreeSet<_>>();
        let mut routes_by_handler: BTreeMap<String, Vec<GoRoute>> = BTreeMap::new();
        let mut summary_candidates: BTreeMap<String, Vec<Vec<MongoParameterSummary>>> =
            BTreeMap::new();
        let mut sql_summary_candidates: BTreeMap<String, Vec<SqlParameterSummary>> =
            BTreeMap::new();
        let mut ldap_summary_candidates: BTreeMap<String, Vec<LdapParameterSummary>> =
            BTreeMap::new();
        let mut cookie_return_helpers = BTreeSet::new();
        let mut session_value_helpers = BTreeSet::new();
        let uses_cookie_session_auth = sources.iter().any(|(_, _, source)| {
            source.contains("sessions.NewCookieStore(")
                || source.contains("sessions.NewFilesystemStore(")
        });
        let has_csrf_control = sources
            .iter()
            .any(|(_, _, source)| source_has_csrf_control(source));

        for (_, _, source) in &sources {
            collect_routes(source, &function_names, &mut routes_by_handler);
            collect_mongo_summaries(source, &mut summary_candidates);
            collect_sql_summaries(source, &mut sql_summary_candidates);
            collect_ldap_summaries(source, &mut ldap_summary_candidates);
            collect_cookie_return_helpers(source, &mut cookie_return_helpers);
            collect_session_value_helpers(source, &mut session_value_helpers);
        }
        for routes in routes_by_handler.values_mut() {
            routes.sort_by(|left, right| {
                left.method
                    .cmp(&right.method)
                    .then_with(|| left.path.cmp(&right.path))
                    .then_with(|| left.target_hint.cmp(&right.target_hint))
                    .then_with(|| left.guards.cmp(&right.guards))
            });
            routes.dedup();
        }
        let mongo_parameter_summaries = summary_candidates
            .into_iter()
            .filter_map(|(name, candidates)| {
                (candidates.len() == 1).then(|| (name, candidates.into_iter().next().unwrap()))
            })
            .collect();
        let sql_parameter_summaries = sql_summary_candidates
            .into_iter()
            .filter_map(|(name, candidates)| {
                (candidates.len() == 1).then(|| (name, candidates.into_iter().next().unwrap()))
            })
            .collect();
        let ldap_parameter_summaries = ldap_summary_candidates
            .into_iter()
            .filter_map(|(name, candidates)| {
                (candidates.len() == 1).then(|| (name, candidates.into_iter().next().unwrap()))
            })
            .collect();
        Self {
            routes_by_handler,
            mongo_parameter_summaries,
            sql_parameter_summaries,
            ldap_parameter_summaries,
            cookie_return_helpers,
            session_value_helpers,
            uses_cookie_session_auth,
            has_csrf_control,
        }
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
        if language != Language::Go {
            return;
        }
        let calls = root.dfs().filter_map(call_site).collect::<Vec<_>>();
        let file_text = root.text();
        let uses_mongo = file_text.contains("go.mongodb.org/mongo-driver/mongo");
        let uses_gorm = file_text.contains("github.com/jinzhu/gorm");
        let body_values = calls
            .iter()
            .filter(|call| call.callee == "io.ReadAll" && is_request_body(call.arguments.first()))
            .filter_map(|call| assigned_identifier(&call.node))
            .collect::<BTreeSet<_>>();
        let query_values = calls
            .iter()
            .filter(|call| call.callee.ends_with(".URL.Query"))
            .filter_map(|call| assigned_identifier(&call.node))
            .collect::<BTreeSet<_>>();
        let decoded_request_values = calls
            .iter()
            .filter(|call| call.callee == "json.Unmarshal")
            .filter(|call| {
                call.arguments
                    .first()
                    .is_some_and(|argument| body_values.contains(argument.text().trim()))
            })
            .filter_map(|call| {
                call.arguments
                    .get(1)
                    .map(|argument| argument.text().trim().trim_start_matches('&').to_string())
            })
            .collect::<BTreeSet<_>>();

        let mut emitted_resource_filters = BTreeSet::new();
        for call in &calls {
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            if call.callee == "io.ReadAll" && is_request_body(call.arguments.first()) {
                push(
                    path,
                    &call.node,
                    "go-net-http-request-body",
                    EvidenceKind::Source,
                    Capability::HttpRequestData,
                    capture_first(path, "body", call),
                    &["CWE-20"],
                    &["http", "request", "body", "net-http"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if call.callee == "mux.Vars" && is_request(call.arguments.first()) {
                push(
                    path,
                    &call.node,
                    "go-gorilla-mux-route-variables",
                    EvidenceKind::Source,
                    Capability::HttpRequestData,
                    capture_first(path, "request", call),
                    &["CWE-20"],
                    &["http", "request", "path-parameter", "gorilla-mux"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if call.callee.ends_with(".ParseUnverified") {
                push(
                    path,
                    &call.node,
                    "go-jwt-parse-unverified-review",
                    EvidenceKind::SensitiveOperation,
                    Capability::Authentication,
                    capture_first(path, "token", call),
                    &["CWE-347"],
                    &["authentication", "jwt", "claims", "unverified"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if terminal_name(&call.callee) == "Get"
                && call
                    .callee
                    .rsplit_once('.')
                    .is_some_and(|(receiver, _)| query_values.contains(receiver))
                && call.arguments.first().is_some_and(|argument| {
                    matches!(
                        compact(argument.text().as_ref()).as_str(),
                        "\"token\"" | "'token'"
                    )
                })
            {
                push(
                    path,
                    &call.node,
                    "go-query-string-credential",
                    EvidenceKind::Source,
                    Capability::CredentialMaterial,
                    capture_first(path, "credential", call),
                    &["CWE-598"],
                    &["http", "credential", "query-string", "token"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if uses_mongo && let Some((operation, role)) = mongo_operation(&call.callee) {
                let capture_name = if role == MongoParameterRole::Filter {
                    "filter"
                } else {
                    "document"
                };
                let captures = call
                    .arguments
                    .get(mongo_value_index(operation, role))
                    .map(|argument| {
                        BTreeMap::from([(capture_name.to_string(), capture(path, argument))])
                    })
                    .unwrap_or_default();
                let (rule_id, capability, cwes, role_tag) = if role == MongoParameterRole::Filter {
                    (
                        "go-mongodb-query",
                        Capability::DatabaseQuery,
                        &["CWE-943"][..],
                        "query",
                    )
                } else {
                    (
                        "go-mongodb-write",
                        Capability::ResourceAccess,
                        &["CWE-915", "CWE-639"][..],
                        "write",
                    )
                };
                push(
                    path,
                    &call.node,
                    rule_id,
                    EvidenceKind::SensitiveOperation,
                    capability,
                    captures,
                    cwes,
                    &["database", "mongodb", role_tag, operation],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if uses_gorm && matches!(terminal_name(&call.callee), "Where" | "Raw" | "Exec") {
                let mut captures = capture_first(path, "query", call);
                if call.arguments.len() > 1 {
                    captures.insert("parameters".to_string(), capture(path, &call.arguments[1]));
                }
                push(
                    path,
                    &call.node,
                    "go-gorm-query",
                    EvidenceKind::Sink,
                    Capability::DatabaseQuery,
                    captures,
                    &["CWE-89"],
                    &["database", "gorm", terminal_name(&call.callee)],
                    Confidence::Medium,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            let target = terminal_name(&call.callee);
            if let Some(indices) = self.mongo_parameter_summaries.get(target) {
                for summary in indices {
                    let Some(argument) = call.arguments.get(summary.index) else {
                        continue;
                    };
                    let request_object = decoded_request_values.contains(argument.text().trim());
                    let (rule_id, capability, cwes, role_tag, input_role) =
                        match (request_object, summary.role, summary.dynamic_object) {
                            (true, MongoParameterRole::Filter, true) => (
                                "go-request-object-mongodb-filter",
                                Capability::DatabaseQuery,
                                &["CWE-943"][..],
                                "request-object-filter",
                                "nosql_query",
                            ),
                            (true, MongoParameterRole::Write, _) => (
                                "go-request-object-mongodb-write",
                                Capability::ResourceAccess,
                                &["CWE-915", "CWE-639"][..],
                                "request-object-write",
                                "assigned_fields",
                            ),
                            (_, MongoParameterRole::Filter, true) => (
                                "go-mongodb-parameter-query-summary",
                                Capability::DatabaseQuery,
                                &["CWE-943"][..],
                                "parameter-filter",
                                "nosql_query",
                            ),
                            (_, MongoParameterRole::Filter, false) => (
                                "go-mongodb-parameter-resource-summary",
                                Capability::ResourceAccess,
                                &["CWE-639"][..],
                                "resource-filter",
                                "filter",
                            ),
                            (false, MongoParameterRole::Write, _) => (
                                "go-mongodb-parameter-write-summary",
                                Capability::ResourceAccess,
                                &["CWE-639", "CWE-915"][..],
                                "parameter-write",
                                "assigned_fields",
                            ),
                        };
                    push(
                        path,
                        &call.node,
                        rule_id,
                        EvidenceKind::SensitiveOperation,
                        capability,
                        BTreeMap::from([
                            (input_role.to_string(), capture(path, argument)),
                            (
                                "target".to_string(),
                                Capture {
                                    text: target.to_string(),
                                    location: location(path, &call.node),
                                },
                            ),
                        ]),
                        cwes,
                        &["database", "mongodb", "project-summary", role_tag],
                        if request_object {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        },
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            if let Some(summary) = self.sql_parameter_summaries.get(target)
                && let Some((index, argument)) = summary.indices.iter().find_map(|index| {
                    call.arguments
                        .get(*index)
                        .map(|argument| (*index, argument))
                })
            {
                let parameterized = summary.role == SqlParameterRole::Parameterized;
                push(
                    path,
                    &call.node,
                    if parameterized {
                        "go-sql-parameterization-summary-control"
                    } else {
                        "go-sql-parameter-query-summary"
                    },
                    if parameterized {
                        EvidenceKind::Sanitizer
                    } else {
                        EvidenceKind::Sink
                    },
                    if parameterized {
                        Capability::SqlParameterization
                    } else {
                        Capability::DatabaseQuery
                    },
                    BTreeMap::from([
                        (
                            if parameterized {
                                "bound_input"
                            } else {
                                "query"
                            }
                            .to_string(),
                            capture(path, argument),
                        ),
                        (
                            "target".to_string(),
                            Capture {
                                text: target.to_string(),
                                location: location(path, &call.node),
                            },
                        ),
                        (
                            "parameter_index".to_string(),
                            Capture {
                                text: index.to_string(),
                                location: location(path, argument),
                            },
                        ),
                    ]),
                    &["CWE-89"],
                    &[
                        "database",
                        "database-sql",
                        "project-summary",
                        if parameterized {
                            "parameterized"
                        } else {
                            "dynamic-query"
                        },
                    ],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if let Some(summary) = self.sql_parameter_summaries.get(target) {
                for index in &summary.resource_filter_indices {
                    let Some(argument) = call.arguments.get(*index) else {
                        continue;
                    };
                    let resource_key = (
                        enclosing_symbol(&call.node).unwrap_or_default(),
                        argument.text().trim().to_string(),
                    );
                    if !emitted_resource_filters.insert(resource_key) {
                        continue;
                    }
                    push(
                        path,
                        &call.node,
                        "go-sql-resource-filter-summary",
                        EvidenceKind::Sink,
                        Capability::ResourceAccess,
                        BTreeMap::from([
                            ("filter".to_string(), capture(path, argument)),
                            (
                                "target".to_string(),
                                Capture {
                                    text: target.to_string(),
                                    location: location(path, &call.node),
                                },
                            ),
                        ]),
                        &["CWE-639"],
                        &[
                            "database",
                            "resource-access",
                            "project-summary",
                            "authorization-context-required",
                        ],
                        Confidence::High,
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                    if summary.mutates_resource {
                        self.add_csrf_state_change(
                            path,
                            &call.node,
                            comments,
                            conditional,
                            literals,
                            evidence,
                        );
                    }
                }
            }
            if let Some(summary) = self.ldap_parameter_summaries.get(target)
                && let Some(filter) = call.arguments.get(summary.filter_index)
            {
                push(
                    path,
                    &call.node,
                    "go-ldap-filter-query-summary",
                    EvidenceKind::Sink,
                    Capability::LdapQuery,
                    BTreeMap::from([("filter".to_string(), capture(path, filter))]),
                    &["CWE-90"],
                    &["ldap", "filter", "project-summary", "unique-helper"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if self.cookie_return_helpers.contains(target) {
                let mut values = BTreeMap::from([(
                    "value".to_string(),
                    Capture {
                        text: call.node.text().into_owned(),
                        location: location(path, &call.node),
                    },
                )]);
                if let Some(name) = call.arguments.get(1) {
                    values.insert("name".to_string(), capture(path, name));
                }
                push(
                    path,
                    &call.node,
                    "go-cookie-helper-source",
                    EvidenceKind::Source,
                    Capability::HttpRequestData,
                    values,
                    &["CWE-20"],
                    &["http", "request", "cookie", "unique-helper-summary"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if self.session_value_helpers.contains(target) {
                let mut values = BTreeMap::from([(
                    "identity".to_string(),
                    Capture {
                        text: call.node.text().into_owned(),
                        location: location(path, &call.node),
                    },
                )]);
                if let Some(key) = call.arguments.get(1) {
                    values.insert("key".to_string(), capture(path, key));
                }
                push(
                    path,
                    &call.node,
                    "go-verified-session-value-control",
                    EvidenceKind::Guard,
                    Capability::Authorization,
                    values,
                    &[],
                    &[
                        "authorization",
                        "session",
                        "integrity-verified-cookie-store",
                        "server-policy-input",
                    ],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        for node in root.dfs() {
            let compact_text = compact(node.text().as_ref());
            let query_token = compact_text.contains(".URL.Query()")
                && (compact_text.contains("[\"token\"]") || compact_text.contains("['token']"));
            let child_has_query_token = node.children().any(|child| {
                let child = compact(child.text().as_ref());
                child.contains(".URL.Query()")
                    && (child.contains("[\"token\"]") || child.contains("['token']"))
            });
            if query_token && !child_has_query_token {
                push(
                    path,
                    &node,
                    "go-query-string-credential",
                    EvidenceKind::Source,
                    Capability::CredentialMaterial,
                    BTreeMap::from([("credential".to_string(), capture(path, &node))]),
                    &["CWE-598"],
                    &["http", "credential", "query-string", "token"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    pub(crate) fn annotate(&self, path: &str, language: Language, evidence: &mut [Evidence]) {
        if language != Language::Go {
            return;
        }
        for item in evidence {
            let Some(symbol) = item.enclosing_symbol.as_deref() else {
                continue;
            };
            let Some(routes) = self.routes_by_handler.get(symbol) else {
                continue;
            };
            item.context.http_routes = routes
                .iter()
                .filter(|route| route_matches_path(&route.target_hint, path))
                .map(|route| HttpRouteContext {
                    method: route.method.clone(),
                    path: route.path.clone(),
                    access: route.access,
                    guards: route.guards.clone(),
                })
                .collect();
            if item.rule_id == "go-http-request-data" && !item.context.http_routes.is_empty() {
                item.confidence = Confidence::High;
            }
        }
    }

    fn is_authenticated_state_change(
        &self,
        path: &str,
        node: &Node<'_, StrDoc<SupportLang>>,
    ) -> bool {
        let Some(symbol) = enclosing_symbol(node) else {
            return false;
        };
        self.routes_by_handler.get(&symbol).is_some_and(|routes| {
            routes.iter().any(|route| {
                route_matches_path(&route.target_hint, path)
                    && route.access == HttpRouteAccess::Authenticated
                    && matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn add_csrf_state_change<'tree>(
        &self,
        path: &str,
        node: &Node<'tree, StrDoc<SupportLang>>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !self.uses_cookie_session_auth
            || self.has_csrf_control
            || !self.is_authenticated_state_change(path, node)
        {
            return;
        }
        let source_rule = "go-cookie-authenticated-request-source";
        let sink_rule = "go-cookie-authenticated-state-change-review";
        push(
            path,
            node,
            source_rule,
            EvidenceKind::Source,
            Capability::HttpRequestData,
            BTreeMap::from([("request".to_string(), capture(path, node))]),
            &[],
            &[
                "http",
                "request",
                "cookie-authenticated",
                "state-change-trigger",
            ],
            Confidence::High,
            comments,
            conditional,
            literals,
            evidence,
        );
        push(
            path,
            node,
            sink_rule,
            EvidenceKind::Sink,
            Capability::ResourceAccess,
            BTreeMap::from([("operation".to_string(), capture(path, node))]),
            &["CWE-352"],
            &[
                "csrf",
                "cookie-authenticated",
                "state-change",
                "project-wide-csrf-control-not-observed",
                "review-origin-or-upstream-control",
            ],
            Confidence::High,
            comments,
            conditional,
            literals,
            evidence,
        );
        relate_pair(path, node, source_rule, sink_rule, evidence);
    }
}

fn go_function_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix("func ")?;
            let rest = if rest.starts_with('(') {
                rest.split_once(')')?.1.trim_start()
            } else {
                rest
            };
            let end = rest.find('(')?;
            valid_identifier(&rest[..end]).then(|| rest[..end].to_string())
        })
        .collect()
}

fn collect_routes(
    source: &str,
    functions: &BTreeSet<String>,
    routes: &mut BTreeMap<String, Vec<GoRoute>>,
) {
    for statement in source.lines().filter(|line| line.contains(".HandleFunc(")) {
        let Some(start) = statement.find(".HandleFunc(") else {
            continue;
        };
        let arguments = &statement[start + ".HandleFunc(".len()..];
        let Some((path, rest)) = first_quoted(arguments) else {
            continue;
        };
        let Some(handler) = functions
            .iter()
            .filter(|name| contains_selector(rest, name))
            .max_by_key(|name| rest.rfind(name.as_str()).unwrap_or(0))
        else {
            continue;
        };
        let method = statement
            .split(".Methods(")
            .nth(1)
            .and_then(|text| first_quoted(text).map(|(value, _)| value))
            .unwrap_or_else(|| "ANY".to_string());
        let auth_guard = [
            "SetMiddlewareAuthentication",
            "RequireAuth",
            "AuthMiddleware",
            "JWTMiddleware",
        ]
        .into_iter()
        .find(|guard| statement.contains(guard));
        routes.entry(handler.clone()).or_default().push(GoRoute {
            target_hint: selector_before(rest, handler).unwrap_or_default(),
            method,
            path,
            access: if auth_guard.is_some() {
                HttpRouteAccess::Authenticated
            } else {
                HttpRouteAccess::Unknown
            },
            guards: auth_guard.into_iter().map(str::to_string).collect(),
        });
    }
    for statement in source.lines() {
        let Some((method, marker)) = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
            .into_iter()
            .find_map(|method| {
                let marker = format!(".{method}(");
                statement.contains(&marker).then_some((method, marker))
            })
        else {
            continue;
        };
        let Some(start) = statement.find(&marker) else {
            continue;
        };
        let arguments = &statement[start + marker.len()..];
        let Some((path, rest)) = first_quoted(arguments) else {
            continue;
        };
        let Some(handler) = functions
            .iter()
            .filter(|name| contains_identifier(rest, name))
            .max_by_key(|name| rest.rfind(name.as_str()).unwrap_or(0))
        else {
            continue;
        };
        let auth_guard = ["AuthCheck", "RequireAuth", "Authenticated", "JWTMiddleware"]
            .into_iter()
            .find(|guard| statement.contains(guard));
        routes.entry(handler.clone()).or_default().push(GoRoute {
            target_hint: selector_before(rest, handler).unwrap_or_default(),
            method: method.to_string(),
            path,
            access: if auth_guard.is_some() {
                HttpRouteAccess::Authenticated
            } else {
                HttpRouteAccess::Unknown
            },
            guards: auth_guard.into_iter().map(str::to_string).collect(),
        });
    }
}

fn collect_sql_summaries(source: &str, summaries: &mut BTreeMap<String, Vec<SqlParameterSummary>>) {
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("func ") {
        let start = cursor + relative;
        let Some(open_body_relative) = source[start..].find('{') else {
            break;
        };
        let open_body = start + open_body_relative;
        let Some(close_body) = matching_brace(source, open_body) else {
            break;
        };
        let header = &source[start + 5..open_body];
        let Some((name, parameters)) = parse_function_header(header) else {
            cursor = close_body + 1;
            continue;
        };
        let body = &source[open_body..=close_body];
        let has_execution = [".Query(", ".QueryRow(", ".ExecContext("]
            .iter()
            .any(|operation| body.contains(operation))
            || has_non_process_exec_call(body);
        let parameterized = body.contains(".Prepare(")
            || ((body.contains(".Query(") || body.contains(".Exec(")) && body.contains('?'));
        let unsafe_query = body.contains("fmt.Sprintf(")
            || body.contains(".Query(\"") && body.contains(" + ")
            || body.contains(".Exec(\"") && body.contains(" + ");
        if has_execution && (parameterized || unsafe_query) {
            let indices = parameters
                .iter()
                .enumerate()
                .filter_map(|(index, (parameter, parameter_type))| {
                    (!is_infrastructure_parameter(parameter_type)
                        && contains_identifier(body, parameter))
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            if !indices.is_empty() {
                let lower = body.to_ascii_lowercase();
                let resource_filter_indices = if lower.contains("where ")
                    && !lower.contains("pass=?")
                    && !lower.contains("password")
                {
                    if lower.contains("update ") {
                        indices.last().copied().into_iter().collect()
                    } else if indices.len() == 1 {
                        indices.clone()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                summaries
                    .entry(name)
                    .or_default()
                    .push(SqlParameterSummary {
                        indices,
                        role: if unsafe_query {
                            SqlParameterRole::UnsafeQuery
                        } else {
                            SqlParameterRole::Parameterized
                        },
                        resource_filter_indices,
                        mutates_resource: lower.contains("update ")
                            || lower.contains("delete ")
                            || lower.contains("insert "),
                    });
            }
        }
        cursor = close_body + 1;
    }
}

pub(crate) fn is_known_process_exec(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.field("function")
        .is_some_and(|function| matches!(function.text().trim(), "unix.Exec" | "syscall.Exec"))
}

fn has_non_process_exec_call(source: &str) -> bool {
    let mut rest = source;
    while let Some(index) = rest.find(".Exec(") {
        let prefix = &rest[..index];
        let receiver = prefix
            .rsplit(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default();
        if !matches!(receiver, "unix" | "syscall") {
            return true;
        }
        rest = &rest[index + ".Exec(".len()..];
    }
    false
}

fn collect_ldap_summaries(
    source: &str,
    summaries: &mut BTreeMap<String, Vec<LdapParameterSummary>>,
) {
    if !source.contains(".NewSearchRequest(") {
        return;
    }
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("func ") {
        let start = cursor + relative;
        let Some(open_body_relative) = source[start..].find('{') else {
            break;
        };
        let open_body = start + open_body_relative;
        let Some(close_body) = matching_brace(source, open_body) else {
            break;
        };
        let header = &source[start + 5..open_body];
        let Some((name, parameters)) = parse_function_header(header) else {
            cursor = close_body + 1;
            continue;
        };
        let body = &source[open_body..=close_body];
        if body.contains(".NewSearchRequest(") {
            let compact_body = compact(body);
            for (filter_index, (parameter, parameter_type)) in parameters.iter().enumerate() {
                if !is_infrastructure_parameter(parameter_type)
                    && compact_body.contains(&format!(",false,{parameter},"))
                {
                    summaries
                        .entry(name.clone())
                        .or_default()
                        .push(LdapParameterSummary { filter_index });
                }
            }
        }
        cursor = close_body + 1;
    }
}

fn collect_session_value_helpers(source: &str, helpers: &mut BTreeSet<String>) {
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("func ") {
        let start = cursor + relative;
        let Some(open_body_relative) = source[start..].find('{') else {
            break;
        };
        let open_body = start + open_body_relative;
        let Some(close_body) = matching_brace(source, open_body) else {
            break;
        };
        let header = &source[start + 5..open_body];
        let body = &source[open_body..=close_body];
        if body.contains(".Values[")
            && body.contains(".Get(")
            && body.contains("return ")
            && let Some((name, _)) = parse_function_header(header)
        {
            helpers.insert(name);
        }
        cursor = close_body + 1;
    }
}

fn source_has_csrf_control(source: &str) -> bool {
    let compact = compact(source);
    (source.contains("github.com/gorilla/csrf")
        && (compact.contains("csrf.Protect(")
            || compact.contains("csrf.Secure(")
            || compact.contains("csrf.TrustedOrigins(")))
        || (source.contains("github.com/justinas/nosurf")
            && (compact.contains("nosurf.New(") || compact.contains("nosurf.NewPure(")))
        || compact.contains("csrf.Middleware(")
}

fn collect_cookie_return_helpers(source: &str, helpers: &mut BTreeSet<String>) {
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("func ") {
        let start = cursor + relative;
        let Some(open_body_relative) = source[start..].find('{') else {
            break;
        };
        let open_body = start + open_body_relative;
        let Some(close_body) = matching_brace(source, open_body) else {
            break;
        };
        let header = &source[start + 5..open_body];
        let body = &source[open_body..=close_body];
        if body.contains(".Cookie(")
            && body.contains("return ")
            && body.contains(".Value")
            && let Some((name, _)) = parse_function_header(header)
        {
            helpers.insert(name);
        }
        cursor = close_body + 1;
    }
}

fn collect_mongo_summaries(
    source: &str,
    summaries: &mut BTreeMap<String, Vec<Vec<MongoParameterSummary>>>,
) {
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("func ") {
        let start = cursor + relative;
        let Some(open_body_relative) = source[start..].find('{') else {
            break;
        };
        let open_body = start + open_body_relative;
        let Some(close_body) = matching_brace(source, open_body) else {
            break;
        };
        let header = &source[start + 5..open_body];
        let Some((name, parameters)) = parse_function_header(header) else {
            cursor = close_body + 1;
            continue;
        };
        let body = &source[open_body..=close_body];
        let has_filter = [".Find(", ".FindOne(", ".CountDocuments("]
            .iter()
            .any(|operation| body.contains(operation));
        let has_write = [".UpdateOne(", ".InsertOne("]
            .iter()
            .any(|operation| body.contains(operation));
        if has_filter || has_write {
            let used = parameters
                .iter()
                .enumerate()
                .filter_map(|(index, (parameter, parameter_type))| {
                    if is_infrastructure_parameter(parameter_type)
                        || !contains_identifier(body, parameter)
                    {
                        None
                    } else {
                        Some(MongoParameterSummary {
                            index,
                            role: if has_filter {
                                MongoParameterRole::Filter
                            } else {
                                MongoParameterRole::Write
                            },
                            dynamic_object: compact(parameter_type).contains("bson.M")
                                || compact(parameter_type).starts_with("map["),
                        })
                    }
                })
                .collect::<Vec<_>>();
            if !used.is_empty() {
                summaries.entry(name).or_default().push(used);
            }
        }
        cursor = close_body + 1;
    }
}

fn parse_function_header(header: &str) -> Option<(String, Vec<(String, String)>)> {
    let header = header.trim();
    let header = if header.starts_with('(') {
        header.split_once(')')?.1.trim_start()
    } else {
        header
    };
    let open = header.find('(')?;
    let close = header[open + 1..].find(')')? + open + 1;
    let name = header[..open].trim();
    if !valid_identifier(name) {
        return None;
    }
    let mut names = Vec::new();
    for parameter in header[open + 1..close].split(',') {
        let mut parts = parameter.split_whitespace();
        let first = parts.next().unwrap_or_default();
        if valid_identifier(first) {
            names.push((first.to_string(), parts.collect::<Vec<_>>().join(" ")));
        }
    }
    Some((name.to_string(), names))
}

fn is_infrastructure_parameter(parameter_type: &str) -> bool {
    let compact = compact(parameter_type);
    compact.contains("mongo.Client")
        || compact.contains("gorm.DB")
        || compact.contains("context.Context")
        || compact.ends_with("DB")
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quoted: Option<u8> = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let bytes = source.as_bytes();
    let mut index = open;
    while index < bytes.len() {
        let character = bytes[index];
        let next = bytes.get(index + 1).copied();
        if line_comment {
            if character == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            if character == b'*' && next == Some(b'/') {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(quote) = quoted {
            if escaped {
                escaped = false;
            } else if character == b'\\' && quote != b'`' {
                escaped = true;
            } else if character == quote {
                quoted = None;
            }
            index += 1;
            continue;
        }
        if character == b'/' && next == Some(b'/') {
            line_comment = true;
            index += 2;
        } else if character == b'/' && next == Some(b'*') {
            block_comment = true;
            index += 2;
        } else if matches!(character, b'"' | b'\'' | b'`') {
            quoted = Some(character);
            index += 1;
        } else if character == b'{' {
            depth += 1;
            index += 1;
        } else if character == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
            index += 1;
        } else {
            index += 1;
        }
    }
    None
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let callee = node.text().get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn assigned_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let parent = node.parent()?;
    if !matches!(
        parent.kind().as_ref(),
        "expression_list" | "short_var_declaration"
    ) {
        return parent.parent().and_then(|grandparent| {
            (grandparent.kind().as_ref() == "short_var_declaration")
                .then(|| assignment_lhs(grandparent.text().as_ref()))
                .flatten()
        });
    }
    let declaration = if parent.kind().as_ref() == "short_var_declaration" {
        parent
    } else {
        parent.parent()?
    };
    (declaration.kind().as_ref() == "short_var_declaration")
        .then(|| assignment_lhs(declaration.text().as_ref()))
        .flatten()
}

fn assignment_lhs(text: &str) -> Option<String> {
    Some(
        text.split(":=")
            .next()?
            .trim()
            .split(',')
            .next()?
            .trim()
            .to_string(),
    )
}

fn is_request_body(argument: Option<&Node<'_, StrDoc<SupportLang>>>) -> bool {
    argument.is_some_and(|argument| {
        let text = compact(argument.text().as_ref());
        text == "r.Body" || text == "req.Body" || text == "request.Body"
    })
}

fn is_request(argument: Option<&Node<'_, StrDoc<SupportLang>>>) -> bool {
    argument.is_some_and(|argument| matches!(argument.text().trim(), "r" | "req" | "request"))
}

fn mongo_operation(callee: &str) -> Option<(&'static str, MongoParameterRole)> {
    match terminal_name(callee) {
        "Find" => Some(("find", MongoParameterRole::Filter)),
        "FindOne" => Some(("find-one", MongoParameterRole::Filter)),
        "UpdateOne" => Some(("update-one", MongoParameterRole::Write)),
        "InsertOne" => Some(("insert-one", MongoParameterRole::Write)),
        "CountDocuments" => Some(("count-documents", MongoParameterRole::Filter)),
        _ => None,
    }
}

fn mongo_value_index(operation: &str, role: MongoParameterRole) -> usize {
    match (operation, role) {
        ("update-one", MongoParameterRole::Write) => 2,
        _ => 1,
    }
}

fn terminal_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee).trim()
}

fn first_quoted(text: &str) -> Option<(String, &str)> {
    let start = text.find('"')?;
    let end = text[start + 1..].find('"')? + start + 1;
    Some((text[start + 1..end].to_string(), &text[end + 1..]))
}

fn contains_selector(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + name.len()..].chars().next();
        before == Some('.')
            && after.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

fn selector_before(text: &str, name: &str) -> Option<String> {
    let index = text.rfind(&format!(".{name}"))?;
    let prefix = &text[..index];
    let start = prefix
        .rfind(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .map_or(0, |position| position + 1);
    let selector = &prefix[start..];
    valid_identifier(selector).then(|| selector.to_string())
}

fn route_matches_path(target_hint: &str, path: &str) -> bool {
    if target_hint.is_empty() {
        return true;
    }
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let hint = target_hint.to_ascii_lowercase();
    normalized
        .split('/')
        .any(|part| part == hint || part == format!("{hint}s"))
        || normalized
            .rsplit('/')
            .next()
            .and_then(|file| file.rsplit_once('.').map(|(stem, _)| stem))
            .is_some_and(|stem| stem == hint || stem == format!("{hint}s"))
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    text.match_indices(identifier).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + identifier.len()..].chars().next();
        before.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
            && after.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        })
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture_first(path: &str, name: &str, call: &CallSite<'_>) -> BTreeMap<String, Capture> {
    call.arguments
        .first()
        .map(|argument| BTreeMap::from([(name.to_string(), capture(path, argument))]))
        .unwrap_or_default()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    cwes: &[&str],
    tags: &[&str],
    confidence: Confidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn relate_pair(
    path: &str,
    node: &Node<'_, StrDoc<SupportLang>>,
    left_rule: &str,
    right_rule: &str,
    evidence: &mut [Evidence],
) {
    let left = format!(
        "{path}:{}:{}:{left_rule}",
        node.range().start,
        node.range().end
    );
    let right = format!(
        "{path}:{}:{}:{right_rule}",
        node.range().start,
        node.range().end
    );
    if let Some(item) = evidence.iter_mut().find(|item| item.id == left) {
        item.related_evidence.push(right.clone());
    }
    if let Some(item) = evidence.iter_mut().find(|item| item.id == right) {
        item.related_evidence.push(left);
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: node.range().start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: node.range().end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_authenticated_gorilla_route() {
        let source = r#"
package api
func Handle(w http.ResponseWriter, r *http.Request) {}
func Routes(router *mux.Router) {
  router.HandleFunc("/items/{id}", JSON(RequireAuth(controller.Handle))).Methods("GET")
}
"#;
        let context =
            GoProjectContext::from_sources(std::iter::once(("routes.go", Language::Go, source)));
        let routes = context.routes_by_handler.get("Handle").unwrap();
        assert_eq!(routes[0].path, "/items/{id}");
        assert_eq!(routes[0].method, "GET");
        assert_eq!(routes[0].access, HttpRouteAccess::Authenticated);
    }

    #[test]
    fn keeps_only_unique_mongo_function_summaries() {
        let source = r#"
package api
func Lookup(client *mongo.Client, filter bson.M) error {
  return client.Database("x").Collection("y").FindOne(ctx, filter).Err()
}
"#;
        let context =
            GoProjectContext::from_sources(std::iter::once(("model.go", Language::Go, source)));
        assert_eq!(
            context.mongo_parameter_summaries.get("Lookup"),
            Some(&vec![MongoParameterSummary {
                index: 1,
                role: MongoParameterRole::Filter,
                dynamic_object: true,
            }])
        );
    }

    #[test]
    fn catalogs_exact_ldap_filter_parameter_summary() {
        let source = r#"
package api
func (client *Directory) Search(ctx context.Context, filter string) {
  /* The server doesn't truncate larger result sets. */
  request := ldap.NewSearchRequest("dc=example", 2, 0, 0, 0, false, filter, nil, nil)
  client.conn.Search(request)
}
"#;
        let context =
            GoProjectContext::from_sources(std::iter::once(("ldap.go", Language::Go, source)));
        assert_eq!(
            context.ldap_parameter_summaries.get("Search"),
            Some(&LdapParameterSummary { filter_index: 1 })
        );
    }
}
