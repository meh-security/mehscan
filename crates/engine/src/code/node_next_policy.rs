use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, RuntimeEnvironment,
    SymbolConfidence,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-next-policy";
const OBJECT_INPUT_ENGINE: &str = "ast-grep 0.45.1 + bounded-node-object-input";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_next_policy_observations<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }
    add_nextauth_policy(
        path,
        source,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_pages_ssr_boundaries(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_manual_jwt_policy(
        path,
        source,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_supabase_service_role_review(
        path,
        source,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_middleware_coverage_review(
        path,
        source,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    if next_route_path(path).is_none() {
        return;
    }
    for function in root.dfs().filter(is_exported_http_function) {
        let Some(route) = route_context_for(&function, evidence) else {
            continue;
        };
        add_route_authorization_review(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_whole_body_persistence(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_privilege_assignment_review(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_auth_endpoint_policy_reviews(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_web_file_upload_roles(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_graphql_policy_reviews(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_business_policy_reviews(
            path,
            &function,
            language,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_auth_endpoint_policy_reviews<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let route_path = route.path.to_ascii_lowercase();
    let login = route_path.ends_with("/auth/login");
    let reset = route_path.ends_with("/auth/reset");
    if !login && !reset {
        return;
    }
    let text = compact(&function.text());
    let has_rate_limit = function.dfs().filter_map(call_site).any(|call| {
        let callee = call.callee.to_ascii_lowercase();
        ["ratelimit", "throttle", "consume", "checklimit"]
            .iter()
            .any(|marker| callee.contains(marker))
    });
    if !has_rate_limit {
        push_fact(
            path,
            language,
            "nextjs-auth-rate-limit-review",
            function,
            EvidenceKind::SecurityConfiguration,
            Capability::Authentication,
            vec!["CWE-307"],
            vec![
                "nextjs",
                "authentication",
                "login-or-reset",
                "rate-limit-not-observed",
                "gateway-or-identity-provider-may-own-control",
                "recommendation:review-then-fix-application",
            ],
            Confidence::Medium,
            BTreeMap::from([("auth_handler".to_string(), capture(path, function))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if login
        && text.contains("status:404")
        && text.contains("status:401")
        && text.contains("Noaccountfound")
        && text.contains("Invalidpassword")
    {
        push_fact(
            path,
            language,
            "nextjs-distinct-login-response-review",
            function,
            EvidenceKind::SecurityConfiguration,
            Capability::Authentication,
            vec!["CWE-203"],
            vec![
                "nextjs",
                "authentication",
                "distinct-user-and-password-errors",
                "username-enumeration",
                "recommendation:fix-application",
            ],
            Confidence::High,
            BTreeMap::from([("login_handler".to_string(), capture(path, function))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if login {
        for branch in function
            .dfs()
            .filter(|node| node.kind().as_ref() == "if_statement")
        {
            let Some(condition) = branch.field("condition") else {
                continue;
            };
            let condition_text = compact(&condition.text()).to_ascii_lowercase();
            if !condition_text.contains("password===\"admin\"")
                && !condition_text.contains("password==='admin'")
            {
                continue;
            }
            push_fact(
                path,
                language,
                "nextjs-literal-default-credential",
                &branch,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                vec!["CWE-1392", "CWE-798"],
                vec![
                    "nextjs",
                    "authentication",
                    "literal-default-password",
                    "privileged-login",
                    "recommendation:fix-application",
                ],
                Confidence::High,
                BTreeMap::from([("credential_branch".to_string(), capture(path, &branch))]),
                vec![route.clone()],
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
    if reset {
        for response in function.dfs().filter_map(call_site).filter(|call| {
            call.callee.ends_with("NextResponse.json") || call.callee == "NextResponse.json"
        }) {
            let Some(payload) = response.arguments.first() else {
                continue;
            };
            let payload_text = compact(&payload.text());
            if !payload_text.contains("token:resetToken")
                && !payload_text.contains("token:${resetToken}")
            {
                continue;
            }
            push_fact(
                path,
                language,
                "nextjs-reset-token-response",
                &response.node,
                EvidenceKind::SensitiveOperation,
                Capability::CredentialMaterial,
                vec!["CWE-640"],
                vec![
                    "nextjs",
                    "password-reset",
                    "reset-token-in-http-response",
                    "recommendation:fix-application",
                ],
                Confidence::High,
                BTreeMap::from([("response_payload".to_string(), capture(path, payload))]),
                vec![route.clone()],
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_manual_jwt_policy<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let compact_source = compact(source);
    if !compact_source.contains("createHmac(")
        || !compact_source.contains("base64url")
        || !compact_source.contains(".split(\".\")") && !compact_source.contains(".split('.')")
    {
        return;
    }
    if let Some(secret) = root.dfs().find(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|name| name.text().to_ascii_lowercase().contains("jwt_secret"))
            && node.field("value").is_some_and(|value| {
                let value = compact(&value.text());
                value.contains("process.env.JWT_SECRET")
                    && (value.contains("||\"secret\"") || value.contains("||'secret'"))
            })
    }) {
        push_fact(
            path,
            language,
            "manual-jwt-weak-fallback-secret",
            &secret,
            EvidenceKind::SecurityConfiguration,
            Capability::TokenGeneration,
            vec!["CWE-321"],
            vec![
                "jwt",
                "manual-jwt",
                "environment-secret-with-weak-fallback",
                "recommendation:fix-application",
            ],
            Confidence::High,
            BTreeMap::from([("secret_configuration".to_string(), capture(path, &secret))]),
            Vec::new(),
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for function in root.dfs().filter(is_function) {
        let name = function_name(&function).unwrap_or_default();
        let text = compact(&function.text());
        if name == "signToken"
            && text.contains("createHmac(")
            && text.contains("iat:")
            && !text.contains("exp:")
            && !text.contains("expiresIn:")
        {
            push_fact(
                path,
                language,
                "manual-jwt-without-expiry",
                &function,
                EvidenceKind::SecurityConfiguration,
                Capability::TokenGeneration,
                vec!["CWE-613"],
                vec![
                    "jwt",
                    "manual-jwt",
                    "issued-at-without-expiration",
                    "recommendation:fix-application",
                ],
                Confidence::High,
                BTreeMap::from([("token_issuer".to_string(), capture(path, &function))]),
                Vec::new(),
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if name != "verifyToken" {
            continue;
        }
        for branch in function.dfs().filter(|node| {
            node.kind().as_ref() == "if_statement"
                && nearest_function_range(node) == Some(function.range())
        }) {
            let Some(condition) = branch.field("condition") else {
                continue;
            };
            let condition_text = compact(&condition.text());
            if !condition_text.contains(".alg===\"none\"")
                && !condition_text.contains(".alg==='none'")
                && !condition_text.contains(".alg==\"none\"")
                && !condition_text.contains(".alg=='none'")
            {
                continue;
            }
            let Some(consequence) = branch.field("consequence") else {
                continue;
            };
            let consequence_text = compact(&consequence.text());
            if !consequence_text.contains("returnJSON.parse(")
                || !consequence_text.contains("base64urlDecode(")
            {
                continue;
            }
            push_fact(
                path,
                language,
                "manual-jwt-alg-none-acceptance",
                &branch,
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                vec!["CWE-347", "CWE-345"],
                vec![
                    "jwt",
                    "manual-jwt",
                    "alg-none",
                    "claims-returned-without-signature-verification",
                    "recommendation:fix-application",
                ],
                Confidence::High,
                BTreeMap::from([
                    (
                        "acceptance_condition".to_string(),
                        capture(path, &condition),
                    ),
                    ("accepted_claims".to_string(), capture(path, &consequence)),
                ]),
                Vec::new(),
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_supabase_service_role_review<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !source.contains("from \"@supabase/supabase-js\"")
        && !source.contains("from '@supabase/supabase-js'")
    {
        return;
    }
    if !source.contains("SUPABASE_SERVICE_ROLE_KEY") || !source.contains("supabaseAdmin") {
        return;
    }
    let Some(admin) = root.dfs().find(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == "supabaseAdmin")
            && node
                .field("value")
                .is_some_and(|value| compact(&value.text()).starts_with("createClient("))
    }) else {
        return;
    };
    push_fact(
        path,
        language,
        "supabase-service-role-shared-module-review",
        &admin,
        EvidenceKind::SecurityConfiguration,
        Capability::Authorization,
        vec!["CWE-269"],
        vec![
            "supabase",
            "service-role",
            "privileged-client",
            "shared-module",
            "verify-server-only-import-boundary",
            "verify-row-level-security-ownership",
            "recommendation:review-then-fix-application",
        ],
        Confidence::Medium,
        BTreeMap::from([("privileged_client".to_string(), capture(path, &admin))]),
        Vec::new(),
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_middleware_coverage_review<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        path.replace('\\', "/").rsplit('/').next(),
        Some("middleware.js" | "middleware.jsx" | "middleware.ts" | "middleware.tsx")
    ) || !source.contains("from \"next/server\"") && !source.contains("from 'next/server'")
        || !source.contains("matcher")
    {
        return;
    }
    add_nextauth_middleware_context(
        path,
        source,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    let compact_source = compact(source);
    if !compact_source.contains("/api/:path*")
        || !compact_source.contains("pathname.startsWith(\"/dashboard\")")
            && !compact_source.contains("pathname.startsWith('/dashboard')")
        || compact_source.contains("pathname.startsWith(\"/api\")")
        || compact_source.contains("pathname.startsWith('/api')")
    {
        return;
    }
    let Some(config) = root.dfs().find(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == "config")
    }) else {
        return;
    };
    push_fact(
        path,
        language,
        "nextjs-middleware-auth-coverage-review",
        &config,
        EvidenceKind::SecurityConfiguration,
        Capability::Authorization,
        vec!["CWE-862"],
        vec![
            "nextjs",
            "middleware",
            "matcher-includes-api",
            "auth-condition-covers-dashboard-only",
            "gateway-or-route-local-auth-may-own-control",
            "recommendation:review-then-fix-application",
        ],
        Confidence::High,
        BTreeMap::from([("middleware_config".to_string(), capture(path, &config))]),
        Vec::new(),
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_nextauth_policy<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(next_auth) = default_import_name(source, "next-auth") else {
        return;
    };
    let Some(credentials_provider) = default_import_name(source, "next-auth/providers/credentials")
    else {
        return;
    };
    let Some(next_auth_call) = root.dfs().filter_map(call_site).find(|call| {
        call.callee == next_auth
            && call.arguments.first().is_some_and(|options| {
                compact(&options.text()).contains(&format!("{credentials_provider}("))
            })
    }) else {
        return;
    };
    let Some(options) = next_auth_call.arguments.first() else {
        return;
    };
    let Some(authorize) = options.dfs().find(|node| {
        is_function(node)
            && method_or_property_name(node).as_deref() == Some("authorize")
            && nearest_function_range(node).is_none_or(|range| range.start >= options.range().start)
    }) else {
        return;
    };
    let Some(credentials_name) = function_parameter_names(&authorize).into_iter().next() else {
        return;
    };
    let comparisons = authorize
        .dfs()
        .filter(|node| node.kind().as_ref() == "binary_expression")
        .filter_map(|comparison| {
            let left = comparison.field("left")?;
            let right = comparison.field("right")?;
            let left_text = compact(&left.text());
            let field = left_text.strip_prefix(&format!("{credentials_name}."))?;
            is_string_literal(&right).then_some((field.to_ascii_lowercase(), left, right))
        })
        .collect::<Vec<_>>();
    let identity = comparisons
        .iter()
        .find(|(field, _, _)| matches!(field.as_str(), "username" | "email" | "login"));
    let password = comparisons
        .iter()
        .find(|(field, _, _)| matches!(field.as_str(), "password" | "passcode"));
    let (Some((_, identity_field, _)), Some((_, password_field, password_literal))) =
        (identity, password)
    else {
        return;
    };
    let authorize_text = compact(&authorize.text());
    if !authorize_text.contains("return{") || authorize_text.contains("compare(") {
        return;
    }
    let route = HttpRouteContext {
        method: "ANY".to_string(),
        path: pages_api_route_path(path).unwrap_or_else(|| "/api/auth/[...nextauth]".to_string()),
        access: HttpRouteAccess::Unknown,
        guards: Vec::new(),
    };
    let mut captures = BTreeMap::from([
        ("identity_field".to_string(), capture(path, identity_field)),
        ("password_field".to_string(), capture(path, password_field)),
        (
            "password_literal".to_string(),
            redacted_capture(path, password_literal),
        ),
    ]);
    if let Some(strategy) = options.dfs().find(|node| {
        node.kind().as_ref() == "pair"
            && node
                .field("key")
                .is_some_and(|key| key.text().trim() == "strategy")
            && node.field("value").is_some_and(|value| {
                is_string_literal(&value)
                    && value
                        .text()
                        .trim_matches(['\'', '"'])
                        .eq_ignore_ascii_case("jwt")
            })
    }) {
        captures.insert("session_strategy".to_string(), capture(path, &strategy));
    }
    push_fact(
        path,
        language,
        "nextauth-hardcoded-credentials",
        &authorize,
        EvidenceKind::SecurityConfiguration,
        Capability::Authentication,
        vec!["CWE-798", "CWE-1392"],
        vec![
            "nextjs",
            "nextauth",
            "credentials-provider",
            "literal-username-and-password",
            "application-owned-authentication",
            "recommendation:fix-application",
        ],
        Confidence::High,
        captures,
        vec![route],
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_nextauth_middleware_context<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(get_token) = named_import_name(source, "next-auth/jwt", "getToken") else {
        return;
    };
    let Some(middleware) = root.dfs().find(|node| {
        is_function(node)
            && function_name(node).as_deref() == Some("middleware")
            && node.ancestors().take(3).any(|ancestor| {
                ancestor.kind().as_ref() == "export_statement"
                    || ancestor.text().trim_start().starts_with("export ")
            })
    }) else {
        return;
    };
    let middleware_text = compact(&middleware.text());
    if !middleware_text.contains(&format!("{get_token}("))
        || !middleware_text.contains("if(!token)")
        || !middleware_text.contains("NextResponse.redirect(")
    {
        return;
    }
    let route = HttpRouteContext {
        method: "ANY".to_string(),
        path: "<next-middleware-matcher>".to_string(),
        access: HttpRouteAccess::Authenticated,
        guards: vec![format!("{get_token}:redirects-unauthenticated")],
    };
    push_fact(
        path,
        language,
        "nextauth-middleware-token-guard",
        &middleware,
        EvidenceKind::Guard,
        Capability::Authentication,
        Vec::new(),
        vec![
            "nextjs",
            "nextauth",
            "middleware",
            "token-check",
            "redirects-unauthenticated",
            "coverage-depends-on-matcher-and-route-policy",
        ],
        Confidence::High,
        BTreeMap::from([("middleware_guard".to_string(), capture(path, &middleware))]),
        vec![route],
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_pages_ssr_boundaries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(route_path) = pages_page_route_path(path) else {
        return;
    };
    for function in root.dfs().filter(|node| {
        is_function(node)
            && function_name(node).as_deref() == Some("getServerSideProps")
            && node.ancestors().take(3).any(|ancestor| {
                ancestor.kind().as_ref() == "export_statement"
                    || ancestor.text().trim_start().starts_with("export ")
            })
    }) {
        let route = HttpRouteContext {
            method: "GET".to_string(),
            path: route_path.clone(),
            access: HttpRouteAccess::Unknown,
            guards: Vec::new(),
        };
        push_fact(
            path,
            language,
            "nextjs-pages-ssr-entrypoint",
            &function,
            EvidenceKind::Entrypoint,
            Capability::HttpRequestHandling,
            vec!["CWE-20"],
            vec![
                "nextjs",
                "pages-router",
                "get-server-side-props",
                "entrypoint",
            ],
            Confidence::High,
            BTreeMap::from([("ssr_handler".to_string(), capture(path, &function))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
        let Some(context_name) = function_parameter_names(&function).into_iter().next() else {
            continue;
        };
        for member in function.dfs().filter(|node| {
            node.kind().as_ref() == "member_expression"
                && nearest_function_range(node) == Some(function.range())
        }) {
            let observed = compact(&member.text());
            if ![
                format!("{context_name}.query"),
                format!("{context_name}.params"),
                format!("{context_name}.req.cookies"),
                format!("{context_name}.req.headers"),
            ]
            .iter()
            .any(|prefix| observed == *prefix || observed.starts_with(&format!("{prefix}.")))
            {
                continue;
            }
            push_fact(
                path,
                language,
                "nextjs-pages-ssr-request-source",
                &member,
                EvidenceKind::Source,
                Capability::HttpRequestData,
                vec!["CWE-20"],
                vec![
                    "nextjs",
                    "pages-router",
                    "get-server-side-props",
                    "attacker-controlled",
                ],
                Confidence::High,
                BTreeMap::from([("value".to_string(), capture(path, &member))]),
                vec![route.clone()],
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_route_authorization_review<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if matches!(
        route.access,
        HttpRouteAccess::Authenticated | HttpRouteAccess::RoleRestricted | HttpRouteAccess::Denied
    ) {
        return;
    }
    let lower_path = route.path.to_ascii_lowercase();
    let text = compact(&function.text());
    let administrative = lower_path.contains("/admin/");
    let resource_by_id = lower_path.contains("[id]")
        && ["getById(", "updateRow(", "deleteRow("]
            .iter()
            .any(|operation| text.contains(operation));
    let task_collection = lower_path == "/api/tasks"
        && ["query(\"tasks\"", "insertRow(\"tasks\""]
            .iter()
            .any(|operation| text.contains(operation));
    if !administrative && !resource_by_id && !task_collection {
        return;
    }
    let (cwe, policy, confidence) = if resource_by_id {
        (
            "CWE-639",
            "resource-owner-or-tenant-check-not-observed",
            Confidence::High,
        )
    } else if administrative {
        (
            "CWE-862",
            "administrative-authorization-not-observed",
            Confidence::High,
        )
    } else {
        (
            "CWE-862",
            "route-authentication-not-observed",
            Confidence::Medium,
        )
    };
    push_fact(
        path,
        language,
        "nextjs-route-authorization-review",
        function,
        EvidenceKind::SecurityConfiguration,
        Capability::Authorization,
        vec![cwe],
        vec![
            "nextjs",
            "app-router",
            policy,
            "middleware-gateway-or-database-policy-may-own-control",
            "recommendation:review-then-fix-application",
        ],
        confidence,
        BTreeMap::from([("handler".to_string(), capture(path, function))]),
        vec![route.clone()],
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_whole_body_persistence<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let body_bindings = direct_request_body_bindings(function);
    if body_bindings.is_empty() {
        return;
    }
    for call in function.dfs().filter_map(call_site) {
        if call.callee.rsplit('.').next() != Some("updateRow") || call.arguments.len() < 3 {
            continue;
        }
        let assigned = &call.arguments[2];
        let assigned_name = assigned.text().trim().to_string();
        if !body_bindings.iter().any(|name| name == &assigned_name) {
            continue;
        }
        let related = evidence
            .iter()
            .filter(|item| {
                item.kind == EvidenceKind::Source
                    && item.capability == Capability::HttpRequestData
                    && item.location.path == path
                    && item.location.start.byte_offset >= function.range().start
                    && item.location.end.byte_offset <= function.range().end
                    && item
                        .captures
                        .get("value")
                        .is_some_and(|value| value.text.trim() == assigned_name)
            })
            .map(|item| item.id.clone())
            .collect();
        let previous_len = evidence.len();
        push_fact(
            path,
            language,
            "nextjs-whole-body-persistence",
            &call.node,
            EvidenceKind::Sink,
            Capability::ResourceAccess,
            vec!["CWE-915"],
            vec![
                "nextjs",
                "mass-assignment",
                "request-object-written-whole",
                "verify-model-field-allowlist",
                "recommendation:fix-application",
            ],
            Confidence::High,
            BTreeMap::from([("assigned_fields".to_string(), capture(path, assigned))]),
            vec![route.clone()],
            related,
            comments,
            conditional,
            literals,
            evidence,
        );
        if evidence.len() > previous_len
            && let Some(item) = evidence.last_mut()
            && item.rule_id.ends_with("nextjs-whole-body-persistence")
        {
            item.provenance.engine = OBJECT_INPUT_ENGINE.to_string();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_privilege_assignment_review<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let text = compact(&function.text());
    if !text.contains("request.json()")
        || !text.contains("updateRow(\"profiles\"")
        || !text.contains("is_admin:role===\"admin\"") && !text.contains("is_admin:role==='admin'")
    {
        return;
    }
    let Some(call) = function.dfs().filter_map(call_site).find(|call| {
        call.callee.rsplit('.').next() == Some("updateRow")
            && compact(&call.node.text()).contains("is_admin:role")
    }) else {
        return;
    };
    push_fact(
        path,
        language,
        "nextjs-client-controlled-privilege-assignment",
        &call.node,
        EvidenceKind::SensitiveOperation,
        Capability::Authorization,
        vec!["CWE-269", "CWE-915"],
        vec![
            "nextjs",
            "privilege-assignment",
            "client-controlled-role",
            "no-admin-guard-observed",
            "recommendation:fix-application",
        ],
        Confidence::High,
        BTreeMap::from([("privilege_update".to_string(), capture(path, &call.node))]),
        vec![route.clone()],
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_web_file_upload_roles<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let files = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = compact(&declaration.field("value")?.text());
            (name.kind().as_ref() == "identifier"
                && value.contains(".get(")
                && function.dfs().any(|candidate| {
                    candidate.kind().as_ref() == "variable_declarator"
                        && candidate.field("value").is_some_and(|origin| {
                            compact(&origin.text()).contains("request.formData()")
                        })
                }))
            .then(|| name.text().trim().to_string())
        })
        .collect::<Vec<_>>();
    for filename in function.dfs().filter(|node| {
        node.kind().as_ref() == "member_expression"
            && files
                .iter()
                .any(|file| compact(&node.text()) == format!("{file}.name"))
    }) {
        push_fact(
            path,
            language,
            "nextjs-web-file-uploaded-path",
            &filename,
            EvidenceKind::Source,
            Capability::UploadedFilePath,
            vec!["CWE-434", "CWE-22"],
            vec![
                "nextjs",
                "web-file",
                "uploaded-filename",
                "attacker-controlled",
                "verify-generated-name-and-public-serving-policy",
            ],
            Confidence::High,
            BTreeMap::from([("path".to_string(), capture(path, &filename))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_graphql_policy_reviews<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let text = compact(&function.text());
    if !text.contains("__schema") && !text.contains("__type") {
        return;
    }
    if let Some(branch) = function.dfs().find(|node| {
        node.kind().as_ref() == "if_statement"
            && node.field("condition").is_some_and(|condition| {
                let condition = compact(&condition.text());
                condition.contains("__schema") || condition.contains("__type")
            })
    }) {
        push_fact(
            path,
            language,
            "nextjs-graphql-introspection-review",
            &branch,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            vec!["CWE-200"],
            vec![
                "nextjs",
                "graphql",
                "introspection-response",
                "configuration-sensitive",
                "recommendation:review-application-policy",
            ],
            Confidence::Medium,
            BTreeMap::from([("introspection_branch".to_string(), capture(path, &branch))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    let has_complexity_control = function.dfs().filter_map(call_site).any(|call| {
        let callee = call.callee.to_ascii_lowercase();
        [
            "depthlimit",
            "maxdepth",
            "complexitylimit",
            "querycomplexity",
        ]
        .iter()
        .any(|control| callee.contains(control))
    });
    if !has_complexity_control {
        push_fact(
            path,
            language,
            "nextjs-graphql-complexity-review",
            function,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            vec!["CWE-400"],
            vec![
                "nextjs",
                "graphql",
                "request-query-accepted",
                "depth-or-complexity-limit-not-observed",
                "gateway-or-graphql-runtime-may-own-control",
                "recommendation:review-then-fix-application",
            ],
            Confidence::Medium,
            BTreeMap::from([("graphql_handler".to_string(), capture(path, function))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_business_policy_reviews<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    route: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let text = compact(&function.text());
    let request_values = request_financial_values(function, path);
    let server_values = server_financial_values(function, path);
    for call in function.dfs().filter_map(call_site) {
        let Some(effect) = financial_effect(path, &call, evidence) else {
            continue;
        };
        if let Some(origin) = request_financial_origin(&effect.value, &request_values) {
            let authority_helper = financial_authority_helper(function, path, &call);
            let mut captures = BTreeMap::from([
                ("financial_effect".to_string(), capture(path, &call.node)),
                ("supplied_value".to_string(), capture(path, &effect.value)),
                ("request_field".to_string(), origin),
                ("effect_field".to_string(), capture(path, &effect.key)),
            ]);
            if let Some(resource) = effect.resource {
                captures.insert("financial_resource".to_string(), capture(path, &resource));
            }
            if let Some(status) = effect.status {
                captures.insert("financial_status".to_string(), capture(path, &status));
            }
            let mut tags = vec![
                "nextjs",
                "business-logic",
                "financial-operation",
                "client-controlled-value",
                "review-invariant:authoritative-value-binding",
                "recommendation:fix-application",
            ];
            if let Some((_helper, helper_capture)) = authority_helper {
                tags.push("related-authority-helper-observed");
                captures.insert("authority_helper".to_string(), helper_capture);
            } else {
                tags.push("authoritative-value-binding-not-observed");
            }
            push_fact(
                path,
                language,
                "nextjs-client-controlled-financial-amount-review",
                &call.node,
                EvidenceKind::SensitiveOperation,
                Capability::ResourceAccess,
                vec!["CWE-840"],
                tags,
                Confidence::High,
                captures,
                vec![route.clone()],
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if let Some((_helper, authority)) =
            server_financial_origin(&effect.value, &server_values)
        {
            let mut captures = BTreeMap::from([
                ("financial_effect".to_string(), capture(path, &call.node)),
                (
                    "authoritative_value".to_string(),
                    capture(path, &effect.value),
                ),
                ("authority_helper".to_string(), authority),
                ("effect_field".to_string(), capture(path, &effect.key)),
            ]);
            if let Some(resource) = effect.resource {
                captures.insert("financial_resource".to_string(), capture(path, &resource));
            }
            push_fact(
                path,
                language,
                "nextjs-authoritative-financial-value-binding-control",
                &call.node,
                EvidenceKind::Validation,
                Capability::ResourceAccess,
                vec!["CWE-840"],
                vec![
                    "nextjs",
                    "business-logic",
                    "financial-operation",
                    "authoritative-value-binding",
                    "server-loaded-value",
                ],
                Confidence::High,
                captures,
                vec![route.clone()],
                Vec::new(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
    if text.contains("currentBalance<amount")
        && text.contains("newBalance=currentBalance-amount")
        && text.contains("updateRow(\"credits\"")
        && !text.to_ascii_lowercase().contains("transaction(")
        && !text.to_ascii_lowercase().contains("forupdate")
        && let Some(call) = function.dfs().filter_map(call_site).find(|call| {
            call.callee.rsplit('.').next() == Some("updateRow")
                && compact(&call.node.text()).contains("balance:newBalance")
        })
    {
        push_fact(
            path,
            language,
            "nextjs-read-check-write-race-review",
            &call.node,
            EvidenceKind::SensitiveOperation,
            Capability::ResourceAccess,
            vec!["CWE-362"],
            vec![
                "nextjs",
                "business-logic",
                "read-check-write",
                "transaction-or-lock-not-observed",
                "database-atomicity-may-own-control",
                "recommendation:review-then-fix-application",
            ],
            Confidence::Medium,
            BTreeMap::from([("balance_write".to_string(), capture(path, &call.node))]),
            vec![route.clone()],
            Vec::new(),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[derive(Clone)]
struct FinancialValueBinding {
    field: String,
    capture: Capture,
}

struct FinancialEffect<'tree> {
    key: Node<'tree, StrDoc<SupportLang>>,
    value: Node<'tree, StrDoc<SupportLang>>,
    resource: Option<Node<'tree, StrDoc<SupportLang>>>,
    status: Option<Node<'tree, StrDoc<SupportLang>>>,
}

fn request_financial_values(
    function: &Node<'_, StrDoc<SupportLang>>,
    path: &str,
) -> BTreeMap<String, FinancialValueBinding> {
    let mut bindings = BTreeMap::new();
    let mut request_objects = BTreeMap::new();
    for declaration in function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| belongs_to_function(node, function))
    {
        let (Some(pattern), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        if !is_request_json_call(&value) {
            continue;
        }
        if pattern.kind().as_ref() == "identifier" {
            request_objects.insert(pattern.text().trim().to_string(), capture(path, &pattern));
            continue;
        }
        if pattern.kind().as_ref() != "object_pattern" {
            continue;
        }
        for property in pattern.children().filter(|child| child.is_named()) {
            if let Some((field, local, node)) = object_pattern_binding(&property) {
                bindings.insert(
                    local,
                    FinancialValueBinding {
                        field,
                        capture: capture(path, &node),
                    },
                );
            }
        }
    }
    for declaration in function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| belongs_to_function(node, function))
    {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        if name.kind().as_ref() != "identifier" {
            continue;
        }
        let expression = compact(&value.text());
        if let Some((_, field)) = request_objects
            .keys()
            .find_map(|object| member_field(&expression, object).map(|field| (object, field)))
        {
            bindings.insert(
                name.text().trim().to_string(),
                FinancialValueBinding {
                    field,
                    capture: capture(path, &value),
                },
            );
        }
    }
    for (object, object_capture) in request_objects {
        bindings.insert(
            format!("{object}.*"),
            FinancialValueBinding {
                field: "*".to_string(),
                capture: object_capture,
            },
        );
    }
    bindings
}

fn server_financial_values(
    function: &Node<'_, StrDoc<SupportLang>>,
    path: &str,
) -> BTreeMap<String, (String, Capture)> {
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| belongs_to_function(node, function))
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = declaration.field("value")?;
            if name.kind().as_ref() != "identifier" || is_request_json_call(&value) {
                return None;
            }
            let call = value.dfs().find_map(call_site)?;
            let helper = authority_helper_name(&call.callee)?;
            let mut helper_capture = capture(path, &call.node);
            helper_capture.text = helper.clone();
            Some((name.text().trim().to_string(), (helper, helper_capture)))
        })
        .collect()
}

fn financial_effect<'tree>(
    path: &str,
    call: &CallSite<'tree>,
    evidence: &[Evidence],
) -> Option<FinancialEffect<'tree>> {
    let operation = call.callee.rsplit('.').next()?.to_ascii_lowercase();
    if !matches!(
        operation.as_str(),
        "create" | "insert" | "insertrow" | "save" | "update" | "upsert"
    ) {
        return None;
    }
    let owned_persistence = evidence.iter().any(|item| {
        item.location.path == path
            && item.location.start.byte_offset == call.node.range().start
            && item.location.end.byte_offset == call.node.range().end
            && item.kind == EvidenceKind::Sink
            && item.capability == Capability::DatabaseQuery
            && item.symbol_resolution.as_ref().is_some_and(|resolution| {
                matches!(
                    resolution.confidence,
                    SymbolConfidence::Exact | SymbolConfidence::High
                )
            })
    });
    if !owned_persistence {
        return None;
    }
    let object = call.arguments.iter().find(|argument| {
        matches!(argument.kind().as_ref(), "object" | "object_expression")
            && object_field(argument, &FINANCIAL_VALUE_FIELDS).is_some()
    })?;
    let (key, value) = object_field(object, &FINANCIAL_VALUE_FIELDS)?;
    let status = object_field(object, &["status", "paymentStatus"])
        .and_then(|(_, status)| financial_completion_status(&status).then_some(status));
    let resource = call
        .arguments
        .iter()
        .find(|argument| quoted_financial_resource(argument.text().trim()))
        .cloned();
    let operation_is_financial = ["payment", "purchase", "order", "invoice", "charge"]
        .iter()
        .any(|marker| call.callee.to_ascii_lowercase().contains(marker));
    (status.is_some() || resource.is_some() || operation_is_financial).then_some(FinancialEffect {
        key,
        value,
        resource,
        status,
    })
}

const FINANCIAL_VALUE_FIELDS: [&str; 7] = [
    "amount",
    "paidAmount",
    "price",
    "subtotal",
    "total",
    "totalAmount",
    "unitAmount",
];

fn object_field<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    names: &[&str],
) -> Option<(
    Node<'tree, StrDoc<SupportLang>>,
    Node<'tree, StrDoc<SupportLang>>,
)> {
    object
        .children()
        .filter(|child| child.is_named())
        .find_map(|property| {
            if matches!(
                property.kind().as_ref(),
                "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
            ) && names.contains(&property.text().trim())
            {
                return Some((property.clone(), property));
            }
            if property.kind().as_ref() != "pair" {
                return None;
            }
            let key = property.field("key")?;
            let name = key.text();
            names
                .contains(&name.trim_matches(['\'', '"']))
                .then(|| property.field("value").map(|value| (key, value)))
                .flatten()
        })
}

fn request_financial_origin(
    value: &Node<'_, StrDoc<SupportLang>>,
    bindings: &BTreeMap<String, FinancialValueBinding>,
) -> Option<Capture> {
    let expression = compact(&value.text());
    if let Some(binding) = bindings.get(&expression) {
        let mut origin = binding.capture.clone();
        origin.text = binding.field.clone();
        return Some(origin);
    }
    bindings.iter().find_map(|(binding, origin)| {
        let object = binding.strip_suffix(".*")?;
        let field = member_field(&expression, object)?;
        let mut capture = origin.capture.clone();
        capture.text = field;
        Some(capture)
    })
}

fn server_financial_origin(
    value: &Node<'_, StrDoc<SupportLang>>,
    bindings: &BTreeMap<String, (String, Capture)>,
) -> Option<(String, Capture)> {
    let expression = compact(&value.text());
    bindings.iter().find_map(|(binding, authority)| {
        (expression == *binding || member_field(&expression, binding).is_some())
            .then(|| authority.clone())
    })
}

fn financial_authority_helper(
    function: &Node<'_, StrDoc<SupportLang>>,
    path: &str,
    effect: &CallSite<'_>,
) -> Option<(String, Capture)> {
    let mut helpers = function
        .dfs()
        .filter_map(call_site)
        .filter(|call| call.node.range().start < effect.node.range().start)
        .filter_map(|call| authority_helper_name(&call.callee).map(|name| (name, call.node)))
        .collect::<Vec<_>>();
    helpers.sort_by(|left, right| left.0.cmp(&right.0));
    helpers.dedup_by(|left, right| left.0 == right.0);
    let [(name, node)] = helpers.as_slice() else {
        return None;
    };
    Some((
        name.clone(),
        Capture {
            text: name.clone(),
            location: location(path, node),
        },
    ))
}

fn authority_helper_name(callee: &str) -> Option<String> {
    let name = callee.rsplit('.').next()?.trim();
    let lower = name.to_ascii_lowercase();
    [
        "catalog", "order", "plan", "price", "pricing", "product", "quote",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    .then(|| name.to_string())
}

fn object_pattern_binding<'tree>(
    property: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(String, String, Node<'tree, StrDoc<SupportLang>>)> {
    if matches!(
        property.kind().as_ref(),
        "shorthand_property_identifier_pattern" | "shorthand_property_identifier"
    ) {
        let name = property.text().trim().to_string();
        return Some((name.clone(), name, property.clone()));
    }
    if property.kind().as_ref() != "pair" {
        return None;
    }
    let key = property.field("key")?;
    let mut value = property.field("value")?;
    if value.kind().as_ref() == "assignment_pattern" {
        value = value.field("left")?;
    }
    (value.kind().as_ref() == "identifier").then(|| {
        (
            key.text().trim_matches(['\'', '"']).to_string(),
            value.text().trim().to_string(),
            value,
        )
    })
}

fn is_request_json_call(value: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let value = compact(&value.text());
    value.ends_with("request.json()") || value.ends_with("req.json()")
}

fn member_field(expression: &str, object: &str) -> Option<String> {
    expression
        .strip_prefix(&format!("{object}."))
        .filter(|field| plain_identifier(field))
        .map(str::to_string)
        .or_else(|| {
            let field = expression
                .strip_prefix(&format!("{object}["))?
                .strip_suffix(']')?;
            let field = field.trim_matches(['\'', '"']);
            plain_identifier(field).then(|| field.to_string())
        })
}

fn quoted_financial_resource(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']).to_ascii_lowercase();
    [
        "charge",
        "invoice",
        "order",
        "payment",
        "purchase",
        "transaction",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn financial_completion_status(value: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        value
            .text()
            .trim_matches(['\'', '"'])
            .to_ascii_lowercase()
            .as_str(),
        "charged" | "completed" | "paid" | "succeeded"
    )
}

fn belongs_to_function(
    node: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    node.ancestors()
        .find(is_function)
        .is_some_and(|owner| owner.range() == function.range())
}

fn plain_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn direct_request_body_bindings(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = compact(&declaration.field("value")?.text());
            (name.kind().as_ref() == "identifier" && value.ends_with("request.json()"))
                .then(|| name.text().trim().to_string())
        })
        .collect()
}

fn route_context_for(
    function: &Node<'_, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Option<HttpRouteContext> {
    evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Entrypoint
                && item
                    .provenance
                    .engine
                    .ends_with("bounded-serverless-boundary")
                && item.location.start.byte_offset == function.range().start
        })?
        .context
        .http_routes
        .first()
        .cloned()
}

fn next_route_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let (_, tail) = normalized.rsplit_once("/app/")?;
    let route = tail
        .strip_suffix("/route.ts")
        .or_else(|| tail.strip_suffix("/route.tsx"))?;
    let parts = route
        .split('/')
        .filter(|part| !part.starts_with('(') && !part.starts_with('@'))
        .collect::<Vec<_>>();
    Some(format!("/{}", parts.join("/")))
}

fn is_exported_http_function(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if !is_function(node) {
        return false;
    }
    let Some(name) = function_name(node) else {
        return false;
    };
    matches!(
        name.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) && node.ancestors().take(3).any(|ancestor| {
        ancestor.kind().as_ref() == "export_statement"
            || ancestor.text().trim_start().starts_with("export ")
    })
}

fn is_function(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
    )
}

fn function_name(function: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    function
        .field("name")
        .map(|name| name.text().trim().to_string())
        .or_else(|| {
            let parent = function.parent()?;
            (parent.kind().as_ref() == "variable_declarator")
                .then(|| parent.field("name"))
                .flatten()
                .map(|name| name.text().trim().to_string())
        })
}

fn nearest_function_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors().find(is_function).map(|node| node.range())
}

fn method_or_property_name(function: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    function
        .field("name")
        .map(|name| name.text().trim().to_string())
        .or_else(|| {
            let parent = function.parent()?;
            (parent.kind().as_ref() == "pair")
                .then(|| parent.field("key"))
                .flatten()
                .map(|key| key.text().trim().to_string())
        })
}

fn function_parameter_names(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let Some(parameters) = function.field("parameters") else {
        return Vec::new();
    };
    parameters
        .children()
        .filter(|parameter| parameter.is_named() && parameter.kind().as_ref() == "identifier")
        .map(|parameter| parameter.text().trim().to_string())
        .collect()
}

fn default_import_name(source: &str, module: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("import ")
            || ![format!("from '{module}'"), format!("from \"{module}\"")]
                .iter()
                .any(|suffix| trimmed.contains(suffix))
        {
            return None;
        }
        let clause = trimmed.strip_prefix("import ")?.split(" from ").next()?;
        let name = clause.split(',').next()?.trim();
        is_simple_identifier(name).then(|| name.to_string())
    })
}

fn named_import_name(source: &str, module: &str, imported: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("import ")
            || ![format!("from '{module}'"), format!("from \"{module}\"")]
                .iter()
                .any(|suffix| trimmed.contains(suffix))
        {
            return None;
        }
        let clause = trimmed.strip_prefix("import ")?.split(" from ").next()?;
        let entries = clause.trim().trim_matches(['{', '}']);
        entries.split(',').find_map(|entry| {
            let words = entry.split_whitespace().collect::<Vec<_>>();
            (words.first().copied() == Some(imported)).then(|| {
                if words.get(1) == Some(&"as") {
                    words.get(2).copied().unwrap_or(imported).to_string()
                } else {
                    imported.to_string()
                }
            })
        })
    })
}

fn is_string_literal(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(node.kind().as_ref(), "string" | "string_fragment") || {
        let text = node.text();
        let text = text.trim();
        text.len() >= 2
            && (text.starts_with('\'') && text.ends_with('\'')
                || text.starts_with('"') && text.ends_with('"'))
    }
}

fn is_simple_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character == '$' || character.is_alphabetic())
        && characters
            .all(|character| character == '_' || character == '$' || character.is_alphanumeric())
}

fn pages_api_route_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let tail = normalized
        .strip_prefix("pages/api/")
        .or_else(|| normalized.rsplit_once("/pages/api/").map(|(_, tail)| tail))?;
    let route = strip_script_extension(tail)?;
    let route = route.strip_suffix("/index").unwrap_or(route);
    Some(format!("/api/{route}"))
}

fn pages_page_route_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let tail = normalized
        .strip_prefix("pages/")
        .or_else(|| normalized.rsplit_once("/pages/").map(|(_, tail)| tail))?;
    if tail.starts_with("api/") {
        return None;
    }
    let route = strip_script_extension(tail)?;
    if route.starts_with('_') || matches!(route, "404" | "500") {
        return None;
    }
    let route = route.strip_suffix("/index").unwrap_or(route);
    (route == "index")
        .then(|| "/".to_string())
        .or_else(|| Some(format!("/{route}")))
}

fn strip_script_extension(path: &str) -> Option<&str> {
    [".js", ".jsx", ".ts", ".tsx"]
        .into_iter()
        .find_map(|extension| path.strip_suffix(extension))
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site<'tree>(node: Node<'tree, StrDoc<SupportLang>>) -> Option<CallSite<'tree>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let callee = node.text().get(..callee_length)?.trim().to_string();
    Some(CallSite {
        node,
        callee,
        arguments: arguments
            .children()
            .filter(|child| child.is_named())
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn push_fact<'tree>(
    path: &str,
    language: Language,
    suffix: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    cwes: Vec<&str>,
    tags: Vec<&str>,
    confidence: Confidence,
    captures: BTreeMap<String, Capture>,
    http_routes: Vec<HttpRouteContext>,
    related_evidence: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    let id = evidence_id(path, &rule_id, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.into_iter().map(str::to_string).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            http_routes,
            runtime_environment: Some(RuntimeEnvironment::Server),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id,
        related_evidence,
    });
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn redacted_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: "<redacted fixed credential>".to_string(),
        location: location(path, node),
    }
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
